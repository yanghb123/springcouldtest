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
import java.util.List;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.ArrayUtils;
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
// @Component
public class CasAuthPreFilterBAK extends ZuulFilter {

	static Logger log = LoggerFactory.getLogger(CasAuthPreFilterBAK.class);

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
		
		return true;
	}

	@Override
	public Object run() {
		RequestContext ctx = RequestContext.getCurrentContext();
		UrlPathHelper h = new UrlPathHelper();
		final String requestURI = h.getPathWithinApplication(ctx.getRequest());
		// HttpServletResponse response = ctx.getResponse();
		// 获取不到，通过阅读源码发现，这里需要在指定routhost为http或者https的时候，会被显示的设置地址。
		// try {
		// URI uri2 = ctx.getRouteHost().toURI();
		// } catch (URISyntaxException e1) {
		// e1.printStackTrace();
		// }
		List<Route> routes = routeLocator.getRoutes();
		routes.forEach(r -> {
			System.out.println(r.getFullPath());
			System.out.println(r.getId());
			System.out.println(r.getLocation());
			System.out.println(r.getPath());
			System.out.println(r.getPrefix());
		});
		Route matchingRoute = routeLocator.getMatchingRoute(requestURI);
		String routerId = matchingRoute.getId();
		if (StringUtils.equals(routerId, "cas")) {
			log.debug("符合CAS路由，开始根据后缀判断提供的服务项目");
			if (StringUtils.startsWith(requestURI, "/cas/")) {
				// 尝试增加判断
				// 放弃，无法改变访问地址URL
				HttpServletRequest request = ctx.getRequest();
				String cookieName = "McloudOAuth";
				String McloudOAuth = getCookie(request, cookieName);
				// 尝试进行head的注入，用来产生识别标识，发现这些哪怕设置进去也无法作用于 CAS的重定向
				// Object object = ctx.get("ctxset");
				// Object object2 = ctx.get("ctxput");
				// List<Pair<String, String>> originResponseHeaders =
				// ctx.getOriginResponseHeaders();
				// Map<String, String> zuulRequestHeaders = ctx.getZuulRequestHeaders();
				// List<Pair<String, String>> zuulResponseHeaders =
				// ctx.getZuulResponseHeaders();
				// // 手动增加标识
				// ctx.set("ctxset", "ctxset");
				// ctx.put("ctxput", "ctx.put");
				// ctx.addZuulRequestHeader("addZuulRequestHeader", "addZuulRequestHeader");
				// ctx.addOriginResponseHeader("addOriginResponseHeader",
				// "addOriginResponseHeader");
				//

				URL url = null;
				try {
					URI uri = ctx.getRouteHost().toURI();
					int port = ctx.getRouteHost().getPort();
					url = UriComponentsBuilder.fromUri(uri).port(port).build().toUri().toURL();
				} catch (MalformedURLException e) {
					e.printStackTrace();
				} catch (URISyntaxException e) {
					e.printStackTrace();
				}
				// ctx.setRouteHost(url);
				//
				if (StringUtils.isNoneBlank(McloudOAuth)) {
					// 如果已经有了缓存，不做任何处理，继续往下走。再SSO的拦截器中会避免向授权服务器发送请求
					// 如果cookie不为空，则尝试改变路径，直接匹配到m/mco里去
					String uri = request.getRequestURI();
					String responseBody = ctx.getResponseBody();
//					System.out.println(responseBody);
					// // new request
					// HttpServletRequestWrapper httpServletRequestWrapper = new
					// HttpServletRequestWrapper(request) {
					//
					// @Override
					// public Enumeration<String> getHeaderNames() {
					// return super.getHeaderNames();
					// }
					//
					// @Override
					// public StringBuffer getRequestURL() {
					// String string = super.getRequestURL().toString();
					// string = StringUtils.replace(string, "cas/mobile3/f", "mobile3/mco/f");
					// StringBuffer sb = new StringBuffer(string);
					// System.out.println("=================sb:" + sb);
					// return sb;
					// }
					//
					// @Override
					// public String getServletPath() {
					// System.out.println("==============getServletPath:" + super.getServletPath());
					// return super.getServletPath();
					// }
					//
					// };
					// //
					// ctx.setRequest(httpServletRequestWrapper);
					// ctx.remove("routeHost");
					// ctx.put(FilterConstants.SERVICE_ID_KEY, "mobile3");
					// return null;
				}
				// 属于CAS单点登陆
				// 通过截取地址栏，获得应该跳转的服务地址
				String remove = StringUtils.remove(requestURI, "/cas/");
				String targetJumpServiceId = StringUtils.substringBefore(remove, "/");
				log.debug("截取到应该跳转的服务项目名为" + targetJumpServiceId);
				ctx.remove("routeHost");
				ctx.put(FilterConstants.SERVICE_ID_KEY, targetJumpServiceId);
			}
		}
		return null;
	}

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
