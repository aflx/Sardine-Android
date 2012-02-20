/*
 * Copyright 2009-2011 Jon Stevens et al.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.aflx.sardine.impl;

import java.io.IOException;
import java.io.InputStream;
import java.net.ProxySelector;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import de.aflx.sardine.util.QName;

import org.apache.http.HttpEntity;
//import org.apache.http.HttpHeaders;
import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.HttpVersion;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.AuthState;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.NTCredentials;
import org.apache.http.auth.UsernamePasswordCredentials;
//import org.apache.http.client.AuthCache;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.params.AuthPolicy;
import org.apache.http.client.protocol.ClientContext;
//import org.apache.http.client.protocol.RequestAcceptEncoding;
//import org.apache.http.client.protocol.ResponseContentEncoding;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.routing.HttpRoutePlanner;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.InputStreamEntity;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.AbstractHttpClient;
//import org.apache.http.impl.client.BasicAuthCache;
import org.apache.http.impl.client.DefaultHttpClient;
//import org.apache.http.impl.client.DefaultRedirectStrategy;
import org.apache.http.impl.conn.ProxySelectorRoutePlanner;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;
import org.apache.http.params.HttpProtocolParams;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.ExecutionContext;
import org.apache.http.protocol.HTTP;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.VersionInfo;

import de.aflx.sardine.DavResource;
import de.aflx.sardine.Sardine;
import de.aflx.sardine.Version;
import de.aflx.sardine.impl.handler.ExistsResponseHandler;
import de.aflx.sardine.impl.handler.LockResponseHandler;
import de.aflx.sardine.impl.handler.MultiStatusResponseHandler;
import de.aflx.sardine.impl.handler.VoidResponseHandler;
import de.aflx.sardine.impl.io.ConsumingInputStream;
import de.aflx.sardine.impl.methods.HttpCopy;
import de.aflx.sardine.impl.methods.HttpLock;
import de.aflx.sardine.impl.methods.HttpMkCol;
import de.aflx.sardine.impl.methods.HttpMove;
import de.aflx.sardine.impl.methods.HttpPropFind;
import de.aflx.sardine.impl.methods.HttpUnlock;
import de.aflx.sardine.model.Allprop;
import de.aflx.sardine.model.Exclusive;
import de.aflx.sardine.model.Lockinfo;
import de.aflx.sardine.model.Lockscope;
import de.aflx.sardine.model.Locktype;
import de.aflx.sardine.model.Multistatus;
import de.aflx.sardine.model.Propfind;
import de.aflx.sardine.model.Response;
import de.aflx.sardine.model.Write;
import de.aflx.sardine.util.Logger;
import de.aflx.sardine.util.SardineUtil;

/**
 * Implementation of the Sardine interface. This is where the meat of the
 * Sardine library lives.
 * 
 * @author jonstevens
 * @version $Id: SardineImpl.java 313 2011-11-18 22:18:37Z dkocher@sudo.ch $
 */
public class SardineImpl implements Sardine {
	private static Logger log = new Logger();

	private static final String UTF_8 = "UTF-8";

	protected HttpRequestBase _currentRequest;
	protected boolean _isAborted = false;
	
	/**
	 * HTTP Implementation
	 */
	private AbstractHttpClient client;

	/**
	 * Local context with authentication cache. Make sure the same context is
	 * used to execute logically related requests.
	 */
	private HttpContext context = new BasicHttpContext();

	/**
	 * Access resources with no authentication
	 */
	public SardineImpl() {
		this(null, null);
	}

	/**
	 * Supports standard authentication mechanisms
	 * 
	 * @param username
	 *            Use in authentication header credentials
	 * @param password
	 *            Use in authentication header credentials
	 */
	public SardineImpl(String username, String password) {
		this(username, password, null);
	}

	/**
	 * @param username
	 *            Use in authentication header credentials
	 * @param password
	 *            Use in authentication header credentials
	 * @param selector
	 *            Proxy configuration
	 */
	public SardineImpl(String username, String password, ProxySelector selector) {
		this.init(this.createDefaultClient(selector), username, password);
	}

	/**
	 * @param http
	 *            Custom client configuration
	 */
	public SardineImpl(AbstractHttpClient http) {
		this(http, null, null);
	}

	/**
	 * @param http
	 *            Custom client configuration
	 * @param username
	 *            Use in authentication header credentials
	 * @param password
	 *            Use in authentication header credentials
	 */
	public SardineImpl(AbstractHttpClient http, String username, String password) {
		this.init(http, username, password);
	}

	private void init(AbstractHttpClient http, String username, String password) {
		this.client = http;
//		this.client.getParams().setParameter(CoreConnectionPNames.SO_TIMEOUT,
//				4000);
//		this.client.getParams().setParameter(
//				CoreConnectionPNames.CONNECTION_TIMEOUT, 1000);
		// this.client.setRedirectStrategy(new DefaultRedirectStrategy()
		// {
		// @Override
		// boolean isRedirected(HttpRequest request, HttpResponse response,
		// HttpContext context) throws ProtocolException
		// {
		// int statusCode = response.getStatusLine().getStatusCode();
		// String method = request.getRequestLine().getMethod();
		// Header locationHeader = response.getFirstHeader("location");
		// switch (statusCode)
		// {
		// case HttpStatus.SC_MOVED_TEMPORARILY:
		// return (method.equalsIgnoreCase(HttpGet.METHOD_NAME)
		// || method.equalsIgnoreCase(HttpHead.METHOD_NAME)
		// || method.equalsIgnoreCase(HttpLock.METHOD_NAME)
		// || method.equalsIgnoreCase(HttpPropFind.METHOD_NAME)) &&
		// (locationHeader != null);
		// case HttpStatus.SC_MOVED_PERMANENTLY:
		// case HttpStatus.SC_TEMPORARY_REDIRECT:
		// return method.equalsIgnoreCase(HttpGet.METHOD_NAME)
		// || method.equalsIgnoreCase(HttpHead.METHOD_NAME)
		// || method.equalsIgnoreCase(HttpLock.METHOD_NAME)
		// || method.equalsIgnoreCase(HttpPropFind.METHOD_NAME);
		// case HttpStatus.SC_SEE_OTHER:
		// return true;
		// default:
		// return false;
		// }
		// }
		//
		// @Override
		// public HttpUriRequest getRedirect(HttpRequest request, HttpResponse
		// response, HttpContext context)
		// throws ProtocolException
		// {
		// String method = request.getRequestLine().getMethod();
		// if (method.equalsIgnoreCase(HttpPropFind.METHOD_NAME))
		// {
		// return new HttpPropFind(this.getLocationURI(request, response,
		// context));
		// }
		// if (method.equalsIgnoreCase(HttpLock.METHOD_NAME))
		// {
		// return new HttpLock(this.getLocationURI(request, response, context));
		// }
		// return super.getRedirect(request, response, context);
		// }
		// });
		this.client.addRequestInterceptor(preemptiveAuth, 0);
		this.setCredentials(username, password);
		log.warn("init");
	}

	public HttpRequestBase getCurrentRequest() {
		return _currentRequest;
	}
	
	public void abort() {
		_isAborted = true;
		_currentRequest.abort();
	}
	
	public boolean isAborted() {
		return _isAborted;
	}
	
	/**
	 * Add credentials to any scope. Supports Basic, Digest and NTLM
	 * authentication methods.
	 * 
	 * @param username
	 *            Use in authentication header credentials
	 * @param password
	 *            Use in authentication header credentials
	 */
	public void setCredentials(String username, String password) {
		this.setCredentials(username, password, "", "");
	}

	/**
	 * @param username
	 *            Use in authentication header credentials
	 * @param password
	 *            Use in authentication header credentials
	 * @param domain
	 *            NTLM authentication
	 * @param workstation
	 *            NTLM authentication
	 */
	public void setCredentials(String username, String password, String domain,
			String workstation) {
		if (username != null) {
			this.client.getCredentialsProvider().setCredentials(
					new AuthScope(AuthScope.ANY_HOST, AuthScope.ANY_PORT,
							AuthScope.ANY_REALM, AuthPolicy.NTLM),
					new NTCredentials(username, password, workstation, domain));
			this.client.getCredentialsProvider().setCredentials(
					new AuthScope(AuthScope.ANY_HOST, AuthScope.ANY_PORT,
							AuthScope.ANY_REALM, AuthPolicy.BASIC),
					new UsernamePasswordCredentials(username, password));
			this.client.getCredentialsProvider().setCredentials(
					new AuthScope(AuthScope.ANY_HOST, AuthScope.ANY_PORT,
							AuthScope.ANY_REALM, AuthPolicy.DIGEST),
					new UsernamePasswordCredentials(username, password));
		}
	}

	HttpRequestInterceptor preemptiveAuth = new HttpRequestInterceptor() {
	    public void process(final HttpRequest request, final HttpContext context) throws HttpException, IOException {
	        AuthState authState = (AuthState) context.getAttribute(ClientContext.TARGET_AUTH_STATE);
	        CredentialsProvider credsProvider = (CredentialsProvider) context.getAttribute(
	                ClientContext.CREDS_PROVIDER);
	        HttpHost targetHost = (HttpHost) context.getAttribute(ExecutionContext.HTTP_TARGET_HOST);
	        
	        if (authState.getAuthScheme() == null) {
	            AuthScope authScope = new AuthScope(targetHost.getHostName(), targetHost.getPort());
	            Credentials creds = credsProvider.getCredentials(authScope);
	            if (creds != null) {
	                authState.setAuthScheme(new BasicScheme());
	                authState.setCredentials(creds);
	            }
	        }
	    }    
	};

	/**
	 * Adds handling of GZIP compression to the client.
	 */
	public void enableCompression() {
		// this.client.addRequestInterceptor(new RequestAcceptEncoding());
		// this.client.addResponseInterceptor(new ResponseContentEncoding());
	}

	/**
	 * Disable GZIP compression header.
	 */
	public void disableCompression() {
		// this.client.removeRequestInterceptorByClass(RequestAcceptEncoding.class);
		// this.client.removeResponseInterceptorByClass(ResponseContentEncoding.class);
	}

	/**
	 * (non-Javadoc)
	 * 
	 * @see de.aflx.sardine.Sardine#enablePreemptiveAuthentication(String)
	 */
	public void enablePreemptiveAuthentication(String hostname) {
		// AuthCache authCache = new BasicAuthCache();
		// // Generate Basic preemptive scheme object and stick it to the local
		// execution context
		// BasicScheme basicAuth = new BasicScheme();
		// SchemeRegistry registry =
		// this.client.getConnectionManager().getSchemeRegistry();
		// // Configure HttpClient to authenticate preemptively by prepopulating
		// the authentication data cache.
		// for (String scheme : registry.getSchemeNames())
		// {
		// int port = registry.getScheme(scheme).getDefaultPort();
		// authCache.put(new HttpHost(hostname), basicAuth);
		// authCache.put(new HttpHost(hostname, -1, scheme), basicAuth);
		// authCache.put(new HttpHost(hostname, port, scheme), basicAuth);
		// }
		// // Add AuthCache to the execution context
		// this.context.setAttribute(ClientContext.AUTH_CACHE, authCache);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * de.aflx.sardine.Sardine#disablePreemptiveAuthentication(java.lang
	 * .String, java.lang.String, int)
	 */
	public void disablePreemptiveAuthentication() {
		// this.context.removeAttribute(ClientContext.AUTH_CACHE);
	}

	/**
	 * (non-Javadoc)
	 * 
	 * @see de.aflx.sardine.Sardine#getResources(java.lang.String)
	 */
	public List<DavResource> getResources(String url) throws IOException {
		return this.list(url);
	}

	/**
	 * (non-Javadoc)
	 * 
	 * @see de.aflx.sardine.Sardine#list(java.lang.String)
	 */
	public List<DavResource> list(String url) throws IOException {
		return this.list(url, 1);
	}

	/**
	 * (non-Javadoc)
	 * 
	 * @see de.aflx.sardine.Sardine#list(java.lang.String)
	 */
	public List<DavResource> list(String url, int depth) throws IOException {
		log.warn("list");
		HttpPropFind entity = new HttpPropFind(url);
		entity.setDepth(Integer.toString(depth));
		Propfind body = new Propfind();
		body.setAllprop(new Allprop());
		// entity.setEntity(new StringEntity(SardineUtil.toXml(body), UTF_8));
		entity.setEntity(new StringEntity("<?xml version=\"1.0\" encoding=\"utf-8\" ?><D:propfind xmlns:D=\"DAV:\">  <D:allprop/></D:propfind>", UTF_8));
		Multistatus multistatus = this.execute(entity,
				new MultiStatusResponseHandler());
		List<Response> responses = multistatus.getResponse();
		log.warn("getResponse");
		List<DavResource> resources = new ArrayList<DavResource>(
				responses.size());
		for (Response response : responses) {
			log.warn("LLL " + response.getHref());
			try {
				resources.add(new DavResource(response));
			} catch (URISyntaxException e) {
				log.warn(String.format("Ignore resource with invalid URI %s",
						response.getHref()));
			}
		}
		return resources;
	}

	public void setCustomProps(String url, Map<String, String> set,
			List<String> remove) throws IOException {
		this.patch(url, SardineUtil.toQName(set), SardineUtil.toQName(remove));
	}

	public List<DavResource> patch(String url, Map<QName, String> setProps)
			throws IOException {
		return this.patch(url, setProps, Collections.<QName> emptyList());
	}

	/**
	 * Creates a {@link de.aflx.sardine.model.Propertyupdate} element
	 * containing all properties to set from setProps and all properties to
	 * remove from removeProps. Note this method will use a
	 * {@link de.aflx.sardine.util.SardineUtil#CUSTOM_NAMESPACE_URI} as
	 * namespace and
	 * {@link de.aflx.sardine.util.SardineUtil#CUSTOM_NAMESPACE_PREFIX}
	 * as prefix.
	 */
	public List<DavResource> patch(String url, Map<QName, String> setProps,
			List<QName> removeProps) throws IOException {
		/*HttpPropPatch entity = new HttpPropPatch(url);
		// Build WebDAV <code>PROPPATCH</code> entity.
		Propertyupdate body = new Propertyupdate();
		// Add properties
		{
			Set set = new Set();
			body.getRemoveOrSet().add(set);
			Prop prop = new Prop();
			// Returns a reference to the live list
			List<Element> any = prop.getAny();
			for (Map.Entry<QName, String> entry : setProps.entrySet()) {
				Element element = SardineUtil.createElement(entry.getKey());
				element.setTextContent(entry.getValue());
				any.add(element);
			}
			set.setProp(prop);
		}
		// Remove properties
		{
			Remove remove = new Remove();
			body.getRemoveOrSet().add(remove);
			Prop prop = new Prop();
			// Returns a reference to the live list
			List<Element> any = prop.getAny();
			for (QName entry : removeProps) {
				Element element = SardineUtil.createElement(entry);
				any.add(element);
			}
			remove.setProp(prop);
		}
		// entity.setEntity(new StringEntity(SardineUtil.toXml(body), UTF_8));
//		MS multistatus = this.execute(entity,
//				new MultiStatusResponseHandler());
//		List<Response> responses = multistatus.getResponse();
		List<DavResource> resources = new ArrayList<DavResource>(
				1);
//		for (Response response : responses) {
//			try {
//				resources.add(new DavResource(response));
//			} catch (URISyntaxException e) {
//				log.warn(String.format("Ignore resource with invalid URI %s",
//						response.getHref().get(0)));
//			}
//		}
		return resources;*/
		return null;
	}

	/**
	 * (non-Javadoc)
	 * 
	 * @see de.aflx.sardine.Sardine#lock(java.lang.String)
	 */
	public String lock(String url) throws IOException {
		HttpLock entity = new HttpLock(url);
		Lockinfo body = new Lockinfo();
		Lockscope scopeType = new Lockscope();
		scopeType.setExclusive(new Exclusive());
		body.setLockscope(scopeType);
		Locktype lockType = new Locktype();
		lockType.setWrite(new Write());
		body.setLocktype(lockType);
		// entity.setEntity(new StringEntity(SardineUtil.toXml(body), UTF_8));
		// Return the lock token
		return this.execute(entity, new LockResponseHandler());
	}

	/**
	 * (non-Javadoc)
	 * 
	 * @see de.aflx.sardine.Sardine#unlock(java.lang.String,
	 *      java.lang.String)
	 */
	public void unlock(String url, String token) throws IOException {
		HttpUnlock entity = new HttpUnlock(url, token);
		Lockinfo body = new Lockinfo();
		Lockscope scopeType = new Lockscope();
		scopeType.setExclusive(new Exclusive());
		body.setLockscope(scopeType);
		Locktype lockType = new Locktype();
		lockType.setWrite(new Write());
		body.setLocktype(lockType);
		this.execute(entity, new VoidResponseHandler());
	}

	/**
	 * (non-Javadoc)
	 * 
	 * @see de.aflx.sardine.Sardine#get(java.lang.String)
	 */
	public ConsumingInputStream get(String url) throws IOException {
		return this.get(url, Collections.<String, String> emptyMap());
	}

	/**
	 * (non-Javadoc)
	 * 
	 * @see de.aflx.sardine.Sardine#get(java.lang.String, java.util.Map)
	 */
	public ConsumingInputStream get(String url, Map<String, String> headers)
			throws IOException {
		HttpGet get = new HttpGet(url);
		for (String header : headers.keySet()) {
			get.addHeader(header, headers.get(header));
		}
		// Must use #execute without handler, otherwise the entity is consumed
		// already after the handler exits.
		HttpResponse response = this.execute(get);
		VoidResponseHandler handler = new VoidResponseHandler();
		try {
			handler.handleResponse(response);
			// Will consume the entity when the stream is closed.
			return new ConsumingInputStream(response);
		} catch (IOException ex) {
			get.abort();
			throw ex;
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see de.aflx.sardine.Sardine#put(java.lang.String, byte[])
	 */
	public void put(String url, byte[] data) throws IOException {
		this.put(url, data, null);
	}

	/**
	 * (non-Javadoc)
	 * 
	 * @see de.aflx.sardine.Sardine#put(java.lang.String, byte[],
	 *      java.lang.String)
	 */
	public void put(String url, byte[] data, String contentType)
			throws IOException {
		ByteArrayEntity entity = new ByteArrayEntity(data);
		this.put(url, entity, contentType, true);
	}

	/**
	 * (non-Javadoc)
	 * 
	 * @see de.aflx.sardine.Sardine#put(java.lang.String,
	 *      java.io.InputStream)
	 */
	public void put(String url, InputStream dataStream) throws IOException {
		this.put(url, dataStream, (String) null);
	}

	/**
	 * (non-Javadoc)
	 * 
	 * @see de.aflx.sardine.Sardine#put(java.lang.String,
	 *      java.io.InputStream, java.lang.String)
	 */
	public void put(String url, InputStream dataStream, String contentType)
			throws IOException {
		this.put(url, dataStream, contentType, true);
	}

	/**
	 * (non-Javadoc)
	 * 
	 * @see de.aflx.sardine.Sardine#put(java.lang.String,
	 *      java.io.InputStream, java.lang.String, boolean)
	 */
	public void put(String url, InputStream dataStream, String contentType,
			boolean expectContinue) throws IOException {
		// A length of -1 means "go until end of stream"
		InputStreamEntity entity = new InputStreamEntity(dataStream, -1);
		this.put(url, entity, contentType, expectContinue);
	}

	/**
	 * (non-Javadoc)
	 * 
	 * @see de.aflx.sardine.Sardine#put(java.lang.String,
	 *      java.io.InputStream, java.util.Map)
	 */
	public void put(String url, InputStream dataStream,
			Map<String, String> headers) throws IOException {
		// A length of -1 means "go until end of stream"
		InputStreamEntity entity = new InputStreamEntity(dataStream, -1);
		this.put(url, entity, headers);
	}

	/**
	 * Upload the entity using <code>PUT</code>
	 * 
	 * @param url
	 *            Resource
	 * @param entity
	 *            The entity to read from
	 * @param contentType
	 *            Content Type header
	 * @param expectContinue
	 *            Add <code>Expect: continue</code> header
	 */
	public void put(String url, HttpEntity entity, String contentType,
			boolean expectContinue) throws IOException {
		Map<String, String> headers = new HashMap<String, String>();
		if (contentType != null) {
			headers.put("Content-Type", contentType);
		}
		if (expectContinue) {
			headers.put(HTTP.EXPECT_DIRECTIVE, HTTP.EXPECT_CONTINUE);
		}
		this.put(url, entity, headers);
	}

	/**
	 * Upload the entity using <code>PUT</code>
	 * 
	 * @param url
	 *            Resource
	 * @param entity
	 *            The entity to read from
	 * @param headers
	 *            Headers to add to request
	 */
	public void put(String url, HttpEntity entity, Map<String, String> headers)
			throws IOException {
		
		HttpPut put = new HttpPut(url);
		_currentRequest = put;
		_isAborted = false;
		
		put.setEntity(entity);
		for (String header : headers.keySet()) {
			put.addHeader(header, headers.get(header));
		}
		if (!put.containsHeader("Content-Type")) {
			put.addHeader("Content-Type", HTTP.DEFAULT_CONTENT_TYPE);
		}
		try {
			this.execute(put, new VoidResponseHandler());
		} catch (HttpResponseException e) {
			if (e.getStatusCode() == HttpStatus.SC_EXPECTATION_FAILED) {
				// Retry with the Expect header removed
				put.removeHeaders(HTTP.EXPECT_DIRECTIVE);
				if (entity.isRepeatable()) {
					this.execute(put, new VoidResponseHandler());
					return;
				}
			}
			
			throw e;
		}
	}

	/**
	 * (non-Javadoc)
	 * 
	 * @see de.aflx.sardine.Sardine#delete(java.lang.String)
	 */
	public void delete(String url) throws IOException {
		HttpDelete delete = new HttpDelete(url);
		this.execute(delete, new VoidResponseHandler());
	}

	/**
	 * (non-Javadoc)
	 * 
	 * @see de.aflx.sardine.Sardine#move(java.lang.String,
	 *      java.lang.String)
	 */
	public void move(String sourceUrl, String destinationUrl)
			throws IOException {
		HttpMove move = new HttpMove(sourceUrl, destinationUrl);
		this.execute(move, new VoidResponseHandler());
	}

	/**
	 * (non-Javadoc)
	 * 
	 * @see de.aflx.sardine.Sardine#copy(java.lang.String,
	 *      java.lang.String)
	 */
	public void copy(String sourceUrl, String destinationUrl)
			throws IOException {
		HttpCopy copy = new HttpCopy(sourceUrl, destinationUrl);
		this.execute(copy, new VoidResponseHandler());
	}

	/**
	 * (non-Javadoc)
	 * 
	 * @see de.aflx.sardine.Sardine#createDirectory(java.lang.String)
	 */
	public void createDirectory(String url) throws IOException {
		HttpMkCol mkcol = new HttpMkCol(url);
		this.execute(mkcol, new VoidResponseHandler());
	}

	/**
	 * (non-Javadoc)
	 * 
	 * @see de.aflx.sardine.Sardine#exists(java.lang.String)
	 */
	public boolean exists(String url) throws IOException {
		HttpHead head = new HttpHead(url);
		return this.execute(head, new ExistsResponseHandler());
	}

	/**
	 * Validate the response using the response handler. Aborts the request if
	 * there is an exception.
	 * 
	 * @param <T>
	 *            Return type
	 * @param request
	 *            Request to execute
	 * @param responseHandler
	 *            Determines the return type.
	 * @return parsed response
	 */
	protected <T> T execute(HttpRequestBase request,
			ResponseHandler<T> responseHandler) throws IOException {
		try {
			// Clear circular redirect cache
			// this.context.removeAttribute(DefaultRedirectStrategy.REDIRECT_LOCATIONS);
			// Execute with response handler
			return this.client.execute(request, responseHandler, this.context);
		} catch (IOException e) {
			request.abort();
			throw e;
		}
	}

	/**
	 * No validation of the response. Aborts the request if there is an
	 * exception.
	 * 
	 * @param request
	 *            Request to execute
	 * @return The response to check the reply status code
	 */
	protected HttpResponse execute(HttpRequestBase request) throws IOException {
		try {
			// Clear circular redirect cache
			// this.context.removeAttribute(DefaultRedirectStrategy.REDIRECT_LOCATIONS);
			// Execute with no response handler
			return this.client.execute(request, this.context);
		} catch (IOException e) {
			request.abort();
			throw e;
		}
	}

	/**
	 * Creates an AbstractHttpClient with all of the defaults.
	 */
	protected AbstractHttpClient createDefaultClient(ProxySelector selector) {
		SchemeRegistry schemeRegistry = this.createDefaultSchemeRegistry();
		ClientConnectionManager cm = this
				.createDefaultConnectionManager(schemeRegistry);
		HttpParams params = this.createDefaultHttpParams();
		AbstractHttpClient client = new DefaultHttpClient(cm, params);
		client.setRoutePlanner(this.createDefaultRoutePlanner(schemeRegistry,
				selector));
		return client;
	}

	/**
	 * Creates default params setting the user agent.
	 * 
	 * @return Basic HTTP parameters with a custom user agent
	 */
	protected HttpParams createDefaultHttpParams() {
		HttpParams params = new BasicHttpParams();
		HttpProtocolParams.setVersion(params, HttpVersion.HTTP_1_1);
		String version = Version.getSpecification();
		if (version == null) {
			version = VersionInfo.UNAVAILABLE;
		}
		HttpProtocolParams.setUserAgent(params, "Sardine/" + version);
		// Only selectively enable this for PUT but not all entity enclosing
		// methods
		HttpProtocolParams.setUseExpectContinue(params, false);
		HttpProtocolParams.setVersion(params, HttpVersion.HTTP_1_1);
		HttpProtocolParams.setContentCharset(params,
				HTTP.DEFAULT_CONTENT_CHARSET);

		HttpConnectionParams.setTcpNoDelay(params, true);
		HttpConnectionParams.setSocketBufferSize(params, 8192);
		return params;
	}

	/**
	 * Creates a new {@link org.apache.http.conn.scheme.SchemeRegistry} for
	 * default ports with socket factories.
	 * 
	 * @return a new {@link org.apache.http.conn.scheme.SchemeRegistry}.
	 */
	protected SchemeRegistry createDefaultSchemeRegistry() {
		SchemeRegistry registry = new SchemeRegistry();
		registry.register(new Scheme("http", this.createDefaultSocketFactory(),
				80));
		registry.register(new Scheme("https", this
				.createDefaultSecureSocketFactory(), 443));
		return registry;
	}

	/**
	 * @return Default socket factory
	 */
	protected PlainSocketFactory createDefaultSocketFactory() {
		return PlainSocketFactory.getSocketFactory();
	}

	/**
	 * @return Default SSL socket factory
	 */
	protected SSLSocketFactory createDefaultSecureSocketFactory() {
		return SSLSocketFactory.getSocketFactory();
	}

	/**
	 * Use fail fast connection manager when connections are not released
	 * properly.
	 * 
	 * @param schemeRegistry
	 *            Protocol registry
	 * @return Default connection manager
	 */
	protected ClientConnectionManager createDefaultConnectionManager(
			SchemeRegistry schemeRegistry) {	
		return new ThreadSafeClientConnManager(createDefaultHttpParams(), schemeRegistry);
	}

	/**
	 * Override to provide proxy configuration
	 * 
	 * @param schemeRegistry
	 *            Protocol registry
	 * @param selector
	 *            Proxy configuration
	 * @return ProxySelectorRoutePlanner configured with schemeRegistry and
	 *         selector
	 */
	protected HttpRoutePlanner createDefaultRoutePlanner(
			SchemeRegistry schemeRegistry, ProxySelector selector) {
		return new ProxySelectorRoutePlanner(schemeRegistry, selector);
	}
}