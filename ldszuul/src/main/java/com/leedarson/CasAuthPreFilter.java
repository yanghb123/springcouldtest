package com.leedarson;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.RandomUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.netflix.zuul.filters.ProxyRequestHelper;
import org.springframework.cloud.netflix.zuul.filters.Route;
import org.springframework.cloud.netflix.zuul.filters.RouteLocator;
import org.springframework.cloud.netflix.zuul.filters.ZuulProperties;
import org.springframework.cloud.netflix.zuul.filters.pre.PreDecorationFilter;
import org.springframework.cloud.netflix.zuul.filters.support.FilterConstants;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UrlPathHelper;

import com.netflix.util.Pair;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.http.HttpServletRequestWrapper;

/**
 * <del> 用以对CAS单点登陆的辅助过滤器，顺序排在decoration之后，主要的工作就是截取需要CAS授权的请求，
 * 然后转发到该请求至目标服务，再在目标服务成功授权之后，把该请求发回到目标服务，因为cas路由得属性strip-prefix是false,因此不会被
 * 截取掉路径里面的任何字符串,能够保证地址栏始终一直符合cas的要求，再加上能根据地址第二位获得转发项目，这样所有项目都可以共用这个路由服务<br>
 * </del>
 * 推翻了第一版本的设计，原因是在部署分布式的情况下，cas登陆成功后后跳转回来的地址指向的那个服务器，并不一定是最开始向cas发送请求的服务器。找了一下也没有让zuul
 * 手动选择具体url的办法，zuul跳转到具体URL使用的是ribbon的负载均衡本身不直接处理url，因此只能放弃固定某一个服务客户端负责cas的思路，因此只能把cas功能抽象出来
 * 单独处理所有项目的CAS请求。
 * 
 * @author howard
 * @Create_Date: 2018年8月9日下午5:22:08
 * @Modified_By: howard
 * @Modified_Date: 2018年10月9日下午6:48:52
 * @Why_and_What_is_modified: <br>
 */
@Component
public class CasAuthPreFilter extends ZuulFilter {

	static Logger log = LoggerFactory.getLogger(CasAuthPreFilter.class);

	@Override
	public int filterOrder() {
		return FilterConstants.PRE_DECORATION_FILTER_ORDER + 1; // run after
		// PreDecoration
		// return FilterConstants.SEND_FORWARD_FILTER_ORDER;
	}

	@Override
	public String filterType() {
		return FilterConstants.PRE_TYPE;
	}

	@Autowired
	private RouteLocator routeLocator;

	@Override
	public boolean shouldFilter() {
		RequestContext ctx = RequestContext.getCurrentContext();
		// return !ctx.containsKey(FilterConstants.FORWARD_TO_KEY) // a filter has
		// // already forwarded
		// && !ctx.containsKey(FilterConstants.SERVICE_ID_KEY); // a filter has already
		// // determined serviceId
		UrlPathHelper h = new UrlPathHelper();
		final String requestURI = h.getPathWithinApplication(ctx.getRequest());
		Route matchingRoute = routeLocator.getMatchingRoute(requestURI);
		String routerId = matchingRoute.getId();
		if (StringUtils.equals(routerId, "cas")) {
			return true;
		} else {
			return false;
		}
	}

	@Override
	public Object run() {
		RequestContext ctx = RequestContext.getCurrentContext();
		UrlPathHelper h = new UrlPathHelper();
		HttpServletRequest request = ctx.getRequest();
		// final String requestURI = h.getPathWithinApplication(ctx.getRequest());
		// String contextPath = request.getContextPath();
		// String localAddr = request.getLocalAddr();
		// String scheme = request.getScheme();
		// String remoteHost = request.getRemoteHost();
		// String requestURI2 = request.getRequestURI();
		// StringBuffer requestURL = request.getRequestURL();
		// HttpServletResponse response = ctx.getResponse();
		// 获取不到，通过阅读源码发现，这里需要在指定routhost为http或者https的时候，会被显示的设置地址。
		// try {
		// URI uri2 = ctx.getRouteHost().toURI();
		// } catch (URISyntaxException e1) {
		// e1.printStackTrace();
		// }
		// 这个方法的作用，是获得当前，微服务所有已经注册了的服务的路由信息
		// 吧已经注册了的casserver服务器加进来。
		List<Route> routes = routeLocator.getRoutes();
		HashSet<String> casServerSet = new java.util.HashSet();
//		casServerSet.add("ldscasserver2");
		routes.forEach(r -> {
			String id = r.getId();
			if (StringUtils.contains(id, "ldscasserver")) {
				casServerSet.add(id);
			}
		});
		// 模拟进行随机授权服务器的负载均衡
		Object[] array = casServerSet.toArray();
		if (array.length > 0) {
			String cookieName = "McloudOAuth";
			String McloudOAuth = getCookie(request, cookieName);
			if (StringUtils.isNoneBlank(McloudOAuth)) {
				// 存在cookies需要做的事情待办
			}
			String urlkey = ctx.get(FilterConstants.REQUEST_URI_KEY).toString();
			if (StringUtils.contains(urlkey, "/ldscasserver")) {
				// 已经是从casserver到cas服务器的请求返回casserver
				// 截取到目标的casserver
				String remove = StringUtils.remove(urlkey, "/cas/");
				String serviceId = StringUtils.substringBefore(remove, "/");
				log.info("====================================选用的CAS服务ID为 ：" + serviceId);
				ctx.remove("routeHost");
				ctx.put(FilterConstants.SERVICE_ID_KEY, serviceId);
			} else {
				Random random = new Random();
				int nextInt = random.nextInt(array.length);
				String serviceId = array[nextInt].toString();
				// 上面这个就是这次选定使用的CAS服务
				String removeFirst = StringUtils.removeFirst(urlkey, "/cas/");
				removeFirst = "/cas/" + serviceId + "/" + removeFirst;
				// 更改访问的url,应该把地址改下?
				// 据说是为了防止后续的一个简单过滤器运行
				ctx.remove("routeHost");
				ctx.put(FilterConstants.SERVICE_ID_KEY, serviceId);
				ctx.put(FilterConstants.REQUEST_URI_KEY, removeFirst);
			}
		} else {
			// 没有注册服务器，就只有报错了
			log.error("用户使用CAS授权，在为服务中却没有发现已经注册的cas服务器。");
		}
		// Route matchingRoute = routeLocator.getMatchingRoute(requestURI);
		// String routerId = matchingRoute.getId();
		// if (StringUtils.equals(routerId, "cas")) {
		// log.debug("符合CAS路由，开始根据后缀判断提供的服务项目");
		// if (StringUtils.startsWith(requestURI, "/cas/")) {
		// // 尝试增加判断
		// // 放弃，无法改变访问地址URL
		// HttpServletRequest request = ctx.getRequest();
		// String cookieName = "McloudOAuth";
		// String McloudOAuth = getCookie(request, cookieName);
		// //
		// if (StringUtils.isNoneBlank(McloudOAuth)) {
		// // 如果已经有了缓存，不做任何处理，继续往下走。再SSO的拦截器中会避免向授权服务器发送请求
		// // 如果cookie不为空，则尝试改变路径，直接匹配到m/mco里去
		// String uri = request.getRequestURI();
		// // return null;
		// Object originalRequestPath = ctx.get(FilterConstants.REQUEST_URI_KEY);
		//
		// }
		// // 属于CAS单点登陆
		// // 通过截取地址栏，获得应该跳转的服务地址
		// String remove = StringUtils.remove(requestURI, "/cas/");
		//
		//
		// }
		// }
		return null;
	}

	// public static void main(String[] args) {
	// HashSet<String> set = new HashSet<>();
	// set.add("s1");
	// set.add("s2");
	// set.add("s3");
	// set.add("s4");
	// Object[] array = set.toArray();
	// for (int i = 0; i < 10; i++) {
	// if (array.length > 0) {
	// Random random = new Random();
	// int nextInt = random.nextInt(array.length);
	// System.out.println(array[nextInt]);
	// }
	// }
	// }

	/**
	 * 获得指定Cookie的值
	 * 
	 * @param name
	 *            名称
	 * @return 值
	 */
	public static String getCookie(HttpServletRequest request, String name) {
		String userName = getCookie(request, null, name, false);
		if (StringUtils.isBlank(userName)) {
			return null;
		} else {
			int index = userName.indexOf("@@");
			if (index == -1) {
				return userName;
			} else {
				return userName.substring(0, index);
			}
		}
	}

	/**
	 * 获得指定Cookie的值
	 * 
	 * @param request
	 *            请求对象
	 * @param response
	 *            响应对象
	 * @param name
	 *            名字
	 * @param isRemove
	 *            是否移除
	 * @return 值
	 */
	public static String getCookie(HttpServletRequest request, HttpServletResponse response, String name,
			boolean isRemove) {
		String value = null;
		Cookie[] cookies = request.getCookies();
		log.debug("get cookies is" + ArrayUtils.toString(cookies));
		if (cookies != null) {
			for (Cookie cookie : cookies) {
				if (cookie.getName().equals(name)) {
					try {
						value = URLDecoder.decode(cookie.getValue(), StandardCharsets.UTF_8.name());
						// break;
					} catch (Exception e) {
						log.error("cookie解码失败:" + cookie.getValue());
						e.printStackTrace();
					}
					if (isRemove) {
						cookie.setMaxAge(0);
						// if
						// (StringUtils.isNotBlank(SpringContextHolder.getApplicationContext().getApplicationName()))
						// {
						// cookie.setPath(SpringContextHolder.getApplicationContext().getApplicationName());
						// } else {
						// cookie.setPath("/");
						// }
						cookie.setPath("/");
						log.debug("开始设置COOKIE:name is " + name + " value is " + value + " setMaxAge is 0");
						response.addCookie(cookie);
					}
				}
			}
		}
		return value;
	}

	public static void setCookie(HttpServletResponse response, String name, String value, int maxAge) {
		Cookie cookie = new Cookie(name, null);
		// if
		// (StringUtils.isNotBlank(SpringContextHolder.getApplicationContext().getApplicationName()))
		// {
		// cookie.setPath(SpringContextHolder.getApplicationContext().getApplicationName());
		// } else {
		// cookie.setPath("/");
		// }
		cookie.setPath("/");
		cookie.setMaxAge(maxAge);
		try {
			if (StringUtils.isNotEmpty(value)) {
				cookie.setValue(URLEncoder.encode(value, "utf-8"));
			}
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		log.debug("开始设置COOKIE:name is " + name + " value is " + value);
		response.addCookie(cookie);
	}

}
