import React, {
  useCallback,
  useEffect,
  useMemo,
  useReducer,
  useRef,
  useState,
} from 'react';
import {
  Auth0Client,
  Auth0ClientOptions,
  PopupLoginOptions,
  PopupConfigOptions,
  GetTokenWithPopupOptions,
  RedirectLoginResult,
  GetTokenSilentlyOptions,
  User,
  RedirectConnectAccountOptions,
  ConnectAccountRedirectResult,
  ResponseType,
  CustomTokenExchangeOptions,
  TokenEndpointResponse
} from '@auth0/auth0-spa-js';
import Auth0Context, {
  Auth0ContextInterface,
  LogoutOptions,
  RedirectLoginOptions,
} from './auth0-context';
import {
  hasAuthParams,
  loginError,
  tokenError,
  deprecateRedirectUri,
} from './utils';
import { reducer } from './reducer';
import { initialAuthState, type AuthState } from './auth-state';

/**
 * Window extensions for Else workspace integration
 */
interface ElseWindowExtensions {
  __elseWrapAuthState?: (
    state: string,
    callbackPath: string,
    iframeContext?: boolean,
    forwardWrappedState?: boolean
  ) => string;
  __elseGetSSOCallbackUrl?: () => string;
  __elseRedirectTopPage?: (url: string) => void;
  __elseAuth0OriginalState?: string;
  ELSE_DEV_ENVIRONMENT?: boolean;
}

/**
 * The account that has been connected during the connect flow.
 */
export type ConnectedAccount = Omit<ConnectAccountRedirectResult, 'appState' | 'response_type'>;

/**
 * The state of the application before the user was redirected to the login page
 * and any account that the user may have connected to.
 */
export type AppState = {
  returnTo?: string;
  connectedAccount?: ConnectedAccount;
  response_type?: ResponseType;
  [key: string]: any; // eslint-disable-line @typescript-eslint/no-explicit-any
};

/**
 * The main configuration to instantiate the `Auth0Provider`.
 */
export interface Auth0ProviderOptions<TUser extends User = User> extends Auth0ClientOptions {
  /**
   * The child nodes your Provider has wrapped
   */
  children?: React.ReactNode;
  /**
   * By default this removes the code and state parameters from the url when you are redirected from the authorize page.
   * It uses `window.history` but you might want to overwrite this if you are using a custom router, like `react-router-dom`
   * See the EXAMPLES.md for more info.
   */
  onRedirectCallback?: (appState?: AppState, user?: TUser) => void;
  /**
   * By default, if the page url has code/state params, the SDK will treat them as Auth0's and attempt to exchange the
   * code for a token. In some cases the code might be for something else (another OAuth SDK perhaps). In these
   * instances you can instruct the client to ignore them eg
   *
   * ```jsx
   * <Auth0Provider
   *   clientId={clientId}
   *   domain={domain}
   *   skipRedirectCallback={window.location.pathname === '/stripe-oauth-callback'}
   * >
   * ```
   */
  skipRedirectCallback?: boolean;
  /**
   * Else SSO mode:
   * - "static_redirect" (default): route login via Nexus callback + wrapped state
   * - "direct": use app-origin redirect_uri and skip state wrapping
   */
  elseSsoMode?: 'static_redirect' | 'direct';
  /**
   * Context to be used when creating the Auth0Provider, defaults to the internally created context.
   *
   * This allows multiple Auth0Providers to be nested within the same application, the context value can then be
   * passed to useAuth0, withAuth0, or withAuthenticationRequired to use that specific Auth0Provider to access
   * auth state and methods specifically tied to the provider that the context belongs to.
   *
   * When using multiple Auth0Providers in a single application you should do the following to ensure sessions are not
   * overwritten:
   *
   * * Configure a different redirect_uri for each Auth0Provider, and set skipRedirectCallback for each provider to ignore
   * the others redirect_uri
   * * If using localstorage for both Auth0Providers, ensure that the audience and scope are different for so that the key
   * used to store data is different
   *
   * For a sample on using multiple Auth0Providers review the [React Account Linking Sample](https://github.com/auth0-samples/auth0-link-accounts-sample/tree/react-variant)
   */
  context?: React.Context<Auth0ContextInterface<TUser>>;
}

/**
 * Replaced by the package version at build time.
 * @ignore
 */
declare const __VERSION__: string;

/**
 * @ignore
 */
const toAuth0ClientOptions = (
  opts: Auth0ProviderOptions
): Auth0ClientOptions => {
  deprecateRedirectUri(opts);

  const { elseSsoMode: _elseSsoMode, ...clientOptions } = opts;
  void _elseSsoMode;

  return {
    ...clientOptions,
    auth0Client: {
      name: 'auth0-react',
      version: __VERSION__,
    },
  };
};

/**
 * @ignore
 */
const defaultOnRedirectCallback = (appState?: AppState): void => {
  window.history.replaceState(
    {},
    document.title,
    appState!.returnTo ?? window.location.pathname
  );
};

/**
 * ```jsx
 * <Auth0Provider
 *   domain={domain}
 *   clientId={clientId}
 *   authorizationParams={{ redirect_uri: window.location.origin }}>
 *   <MyApp />
 * </Auth0Provider>
 * ```
 *
 * Provides the Auth0Context to its child components.
 */
const Auth0Provider = <TUser extends User = User>(opts: Auth0ProviderOptions<TUser>) => {
  const {
    children,
    skipRedirectCallback,
    onRedirectCallback = defaultOnRedirectCallback,
    context = Auth0Context,
    elseSsoMode = 'static_redirect',
    ...clientOpts
  } = opts;
  
  // Detect Else workspace SDK if available
  // We intentionally do NOT override redirect_uri at client initialization.
  // Silent auth (prompt=none, web_message) requires the app origin to receive
  // the postMessage callback; overriding to the SSO router breaks that flow.
  const elseWindow = window as typeof window & ElseWindowExtensions;
  const checkElseWorkspace = () => typeof window !== 'undefined' && 
    typeof elseWindow.__elseWrapAuthState === 'function' &&
    typeof elseWindow.__elseGetSSOCallbackUrl === 'function';
  
  const isElseWorkspace = checkElseWorkspace();
  
  // Keep client options untouched; interactive flows override redirect_uri later.
  const finalClientOpts = (() => {
    if (typeof window !== 'undefined' && elseWindow.ELSE_DEV_ENVIRONMENT && !isElseWorkspace) {
      // SDK env vars are set but SDK functions aren't available yet (async loading)
      console.warn('[Auth0 React SDK] ⚠️ Else workspace detected (ELSE_DEV_ENVIRONMENT=true) but SDK functions not yet available.');
      console.warn('[Auth0 React SDK] ⚠️ loginWithRedirect will override redirect_uri when SDK loads.');
    }
    return clientOpts;
  })();
  
  const [client] = useState(() => {
    // Monkey-patch fetch to route Auth0 API calls through /external_proxy/ for CORS spoofing
    // This only applies in Else workspaces where we need to bypass CORS restrictions
    if (isElseWorkspace && typeof window !== 'undefined') {
      // Extract Auth0 domain from client options
      // The domain can be:
      // - Just the hostname: "tenant.auth0.com" or "auth.somethingelse.ai"
      // - Full URL: "https://tenant.auth0.com" or "https://auth.somethingelse.ai"
      const auth0Domain = finalClientOpts.domain || clientOpts.domain;
      if (!auth0Domain) {
        console.warn('[Auth0 React SDK] ⚠️ No Auth0 domain found in client options, skipping fetch monkey-patch');
        return new Auth0Client(toAuth0ClientOptions(finalClientOpts));
      }
      
      // Normalize domain to hostname (remove protocol if present)
      const normalizedDomain = auth0Domain.replace(/^https?:\/\//, '').split('/')[0];
      if (!normalizedDomain || normalizedDomain.length === 0) {
        console.warn('[Auth0 React SDK] ⚠️ Invalid Auth0 domain format, skipping fetch monkey-patch');
        return new Auth0Client(toAuth0ClientOptions(finalClientOpts));
      }
      
      // At this point, normalizedDomain is guaranteed to be a non-empty string
      // Store it in a const that will be captured by the closure
      const auth0Hostname = normalizedDomain;
      
      // Known Auth0 API endpoints that should be proxied
      const auth0ApiPaths = ['/oauth/token', '/userinfo', '/oauth/revoke'];
      
      const originalFetch = window.fetch;
      const patchedFetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        // auth0Hostname is captured from the closure and is guaranteed to be defined
        // because we return early if normalizedDomain is empty
        // Use non-null assertion since we've validated it above
        const domainToMatch: string = auth0Hostname!;
        
        const url = typeof input === 'string' 
          ? input 
          : input instanceof URL 
            ? input.href 
            : typeof input === 'object' && 'url' in input
              ? input.url
              : String(input);
        
        try {
          const urlObj = new URL(url);
          
          // Skip if this URL is already proxied (to prevent infinite recursion)
          // Check if the origin matches current origin and path starts with /external_proxy/
          if (urlObj.origin === window.location.origin && urlObj.pathname.startsWith('/external_proxy/')) {
            // Already proxied, use original fetch directly
            return originalFetch(input, init);
          }
          
          // Check if this is an Auth0 API call:
          // 1. Hostname must match the Auth0 domain (exact match or subdomain)
          // 2. Path must be a known Auth0 API endpoint
          const hostnameMatches = 
            urlObj.hostname === domainToMatch || 
            urlObj.hostname.endsWith('.' + domainToMatch) ||
            (domainToMatch.includes('auth0.com') && urlObj.hostname.includes('auth0.com'));
          
          const isAuth0ApiPath = auth0ApiPaths.some(path => urlObj.pathname === path || urlObj.pathname.startsWith(path + '/'));
          
          if (hostnameMatches && isAuth0ApiPath && urlObj.protocol.startsWith('http')) {
            // Rewrite URL to go through /external_proxy/
            // https://auth.somethingelse.ai/oauth/token?code=123
            // → http://localhost:2021/external_proxy/auth.somethingelse.ai/oauth/token?code=123
            const proxyUrl = `${window.location.origin}/external_proxy/${urlObj.hostname}${urlObj.pathname}${urlObj.search}${urlObj.hash}`;
            
            console.log('[Auth0 React SDK] 🔄 Routing Auth0 API call through external_proxy:', {
              domain: domainToMatch,
              original: url.substring(0, 150),
              proxied: proxyUrl.substring(0, 150)
            });
            
            return originalFetch(proxyUrl, init);
          }
        } catch (error) {
          // If URL parsing fails, just use original fetch
          console.warn('[Auth0 React SDK] ⚠️ Failed to parse URL for proxy routing:', error);
        }
        
        // Not an Auth0 API call or parsing failed - use original fetch
        return originalFetch(input, init);
      };
      
      // Replace global fetch
      window.fetch = patchedFetch;
      
      console.log('[Auth0 React SDK] ✅ Monkey-patched fetch to route Auth0 API calls through /external_proxy/', {
        auth0Domain: auth0Hostname
      });
    }
    
    return new Auth0Client(toAuth0ClientOptions(finalClientOpts));
  });
  
  // If SDK loads after initialization, log warning
  // Note: We can't update the client after initialization, but loginWithRedirect will override redirect_uri
  useEffect(() => {
    if (!isElseWorkspace && checkElseWorkspace()) {
      // SDK became available after initialization - log warning
      console.warn('[Auth0 React SDK] Else workspace SDK loaded after Auth0Provider initialization. loginWithRedirect will override redirect_uri on demand.');
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const [state, dispatch] = useReducer(reducer<TUser>, initialAuthState  as AuthState<TUser>);
  const didInitialise = useRef(false);

  const handleError = useCallback((error: Error) => {
    dispatch({ type: 'ERROR', error });
    return error;
  }, []);

  useEffect(() => {
    if (didInitialise.current) {
      return;
    }
    didInitialise.current = true;
    (async (): Promise<void> => {
      try {
        let user: TUser | undefined;
        if (hasAuthParams() && !skipRedirectCallback) {
          // Note: In Else workspaces, the state is wrapped with routing information.
          // The wrapped state is stored by the SDK during loginWithRedirect and validated here.
          // Since we forward the wrapped state (forwardWrappedState=true), the SDK receives
          // the same wrapped state it stored, so validation succeeds.
          // The state parameter is validated internally by the SDK and not exposed to user code.
          const { appState = {}, response_type, ...result } = await client.handleRedirectCallback();
          user = await client.getUser();
          appState.response_type = response_type;
          if (response_type === ResponseType.ConnectCode) {
            appState.connectedAccount = result as ConnectedAccount;
          }
          onRedirectCallback(appState, user);
        } else {
          await client.checkSession();
          user = await client.getUser();
        }
        dispatch({ type: 'INITIALISED', user });
      } catch (error) {
        handleError(loginError(error));
      }
    })();
  }, [client, onRedirectCallback, skipRedirectCallback, handleError]);

  const loginWithRedirect = useCallback(
    (opts?: RedirectLoginOptions): Promise<void> => {
      deprecateRedirectUri(opts);

      // Check if running in Else workspace - check dynamically at call time, not closure
      // This ensures we detect the SDK even if it loaded after component initialization
      const elseWindow = window as typeof window & ElseWindowExtensions;
      const hasWrapFunction = typeof elseWindow.__elseWrapAuthState === 'function';
      const hasCallbackFunction = typeof elseWindow.__elseGetSSOCallbackUrl === 'function';
      const isElseWorkspaceNow = typeof window !== 'undefined' && hasWrapFunction && hasCallbackFunction;

      // Debug logging
      if (typeof window !== 'undefined' && elseWindow.ELSE_DEV_ENVIRONMENT) {
        console.log('[Auth0 React SDK] Debug - Else workspace check:', {
          ELSE_DEV_ENVIRONMENT: elseWindow.ELSE_DEV_ENVIRONMENT,
          hasWrapFunction,
          hasCallbackFunction,
          isElseWorkspaceNow,
          wrapFunctionType: typeof elseWindow.__elseWrapAuthState,
          callbackFunctionType: typeof elseWindow.__elseGetSSOCallbackUrl
        });
      }

      if (isElseWorkspaceNow) {
        if (elseSsoMode === 'direct') {
          console.log('[Auth0 React SDK] ✅ Else workspace detected in loginWithRedirect (direct mode)');
          const modifiedOpts: RedirectLoginOptions = opts ? { ...opts } : {};
          if (!modifiedOpts.authorizationParams) {
            modifiedOpts.authorizationParams = {};
          } else {
            modifiedOpts.authorizationParams = { ...modifiedOpts.authorizationParams };
          }

          const originalOpenUrl = modifiedOpts.openUrl;
          modifiedOpts.openUrl = async (url: string) => {
            if (typeof elseWindow.__elseRedirectTopPage === 'function') {
              elseWindow.__elseRedirectTopPage(url);
            } else if (originalOpenUrl) {
              await originalOpenUrl(url);
            } else {
              window.location.href = url;
            }
          };

          return client.loginWithRedirect(modifiedOpts);
        }

        console.log('[Auth0 React SDK] ✅ Else workspace detected in loginWithRedirect, overriding redirect_uri');
        // Clone options to avoid mutating the original
        const modifiedOpts: RedirectLoginOptions = opts ? { ...opts } : {};
        
        // Ensure authorizationParams exists
        if (!modifiedOpts.authorizationParams) {
          modifiedOpts.authorizationParams = {};
        } else {
          modifiedOpts.authorizationParams = { ...modifiedOpts.authorizationParams };
        }

        // Get the callback path from redirect_uri or use default
        const originalRedirectUri = modifiedOpts.authorizationParams.redirect_uri || 
          clientOpts.authorizationParams?.redirect_uri || 
          window.location.origin;
        
        // Extract callback path from redirect_uri
        let callbackPath = '/callback'; // default
        try {
          const redirectUrl = new URL(originalRedirectUri);
          callbackPath = redirectUrl.pathname || '/callback';
        } catch {
          // If URL parsing fails, try to extract path from string
          const match = originalRedirectUri.match(/\/[^?#]*/);
          if (match) {
            callbackPath = match[0];
          }
        }

        // Get original state (if provided) or let Auth0 SDK generate one
        // We'll intercept the URL later to replace the state with our wrapped version
        const originalState = modifiedOpts.authorizationParams.state;
        
        // Don't set state in options - let Auth0 SDK generate it, then we'll replace it in the URL
        // This ensures the SDK stores the state for validation, but we'll send our wrapped version
        
        // Replace redirect_uri with Else's callback URL
        const elseCallbackUrl = elseWindow.__elseGetSSOCallbackUrl!();
        modifiedOpts.authorizationParams.redirect_uri = elseCallbackUrl;
        console.log('[Auth0 React SDK] ✅ Overriding redirect_uri with Else callback URL:', elseCallbackUrl);
        
        // We'll wrap the state in the openUrl callback after Auth0 generates it

        // Store original state for unwrapping in callback
        // Store it in a way that won't conflict with SDK's storage
        if (typeof Storage !== 'undefined') {
          try {
            sessionStorage.setItem('__else_auth0_original_state', originalState);
          } catch {
            // Storage might not be available, use window object as fallback
            elseWindow.__elseAuth0OriginalState = originalState;
          }
        } else {
          elseWindow.__elseAuth0OriginalState = originalState;
        }

        // Use Else's redirect helper for iframe handling via openUrl callback
        // This allows us to intercept the redirect URL and modify the state parameter
        // The Auth0 SDK generates its own state internally, so we need to:
        // 1. Extract the SDK-generated state from the URL
        // 2. Wrap it with Else routing information  
        // 3. Replace it in the URL
        // 4. The SDK will store the wrapped state (since we're replacing it before redirect)
        const originalOpenUrl = modifiedOpts.openUrl;
        modifiedOpts.openUrl = async (url: string) => {
          console.log('[Auth0 React SDK] 🔍 openUrl callback called with URL:', url.substring(0, 200) + '...');
          
          try {
            const authUrl = new URL(url);
            const sdkGeneratedState = authUrl.searchParams.get('state');
            
            if (!sdkGeneratedState) {
              console.warn('[Auth0 React SDK] ⚠️ No state parameter found in auth URL');
              // Still redirect even without state
              if (typeof elseWindow.__elseRedirectTopPage === 'function') {
                elseWindow.__elseRedirectTopPage(url);
              } else if (originalOpenUrl) {
                await originalOpenUrl(url);
              } else {
                window.location.href = url;
              }
              return;
            }
            
            console.log('[Auth0 React SDK] 🔍 SDK generated state:', sdkGeneratedState);
            
            // Wrap the SDK-generated state with Else routing information
            // forwardWrappedState=false because Auth0 SDK validates the ORIGINAL state on callback
            // The backend will unwrap and forward the original state, so SDK validation succeeds
            const wrappedState = elseWindow.__elseWrapAuthState!(
              sdkGeneratedState,
              callbackPath,
              undefined, // auto-detect iframe context
              false // forward original state (Auth0 SDK validates original state, not wrapped)
            );
            
            console.log('[Auth0 React SDK] ✅ Wrapped state:', wrappedState.substring(0, 100) + '...');
            
            // Replace the state parameter with our wrapped state
            authUrl.searchParams.set('state', wrappedState);
            const modifiedUrl = authUrl.toString();
            
            console.log('[Auth0 React SDK] ✅ Modified auth URL with wrapped state');
            console.log('[Auth0 React SDK]   Modified URL preview:', modifiedUrl.substring(0, 200) + '...');
            
            // Use Else's redirect helper if available
            if (typeof elseWindow.__elseRedirectTopPage === 'function') {
              console.log('[Auth0 React SDK] ✅ Using Else redirect helper');
              elseWindow.__elseRedirectTopPage(modifiedUrl);
            } else if (originalOpenUrl) {
              console.log('[Auth0 React SDK] ✅ Using original openUrl');
              await originalOpenUrl(modifiedUrl);
            } else {
              console.log('[Auth0 React SDK] ✅ Using window.location.href fallback');
              window.location.href = modifiedUrl;
            }
          } catch (error) {
            console.error('[Auth0 React SDK] ❌ Failed to modify auth URL:', error);
            // Fallback to original URL if parsing fails
            if (typeof elseWindow.__elseRedirectTopPage === 'function') {
              elseWindow.__elseRedirectTopPage(url);
            } else if (originalOpenUrl) {
              await originalOpenUrl(url);
            } else {
              window.location.href = url;
            }
          }
        };

        // CRITICAL: Always provide openUrl to ensure it's called
        // The Auth0 SDK will call openUrl if provided, otherwise it redirects directly
        // By always providing it, we ensure our interception works
        if (!modifiedOpts.openUrl) {
          // This should never happen since we set it above, but just in case
          modifiedOpts.openUrl = async (url: string) => {
            console.log('[Auth0 React SDK] ⚠️ Fallback openUrl called (should not happen)');
            if (typeof elseWindow.__elseRedirectTopPage === 'function') {
              elseWindow.__elseRedirectTopPage(url);
            } else {
              window.location.href = url;
            }
          };
        }
        
        console.log('[Auth0 React SDK] 🔍 Calling client.loginWithRedirect with openUrl callback');
        
        // Call SDK's loginWithRedirect with modified options
        // The openUrl callback will intercept the URL and replace the state
        // If openUrl isn't called, window.__elseRedirectTopPage in sso.ts will catch it as a fallback
        return client.loginWithRedirect(modifiedOpts);
      }

      // Not in Else workspace - use normal flow
      return client.loginWithRedirect(opts);
    },
    [client, clientOpts, elseSsoMode]
  );

  const loginWithPopup = useCallback(
    async (
      options?: PopupLoginOptions,
      config?: PopupConfigOptions
    ): Promise<void> => {
      dispatch({ type: 'LOGIN_POPUP_STARTED' });
      try {
        await client.loginWithPopup(options, config);
      } catch (error) {
        handleError(loginError(error));
        return;
      }
      const user = await client.getUser();
      dispatch({ type: 'LOGIN_POPUP_COMPLETE', user });
    },
    [client, handleError]
  );

  const logout = useCallback(
    async (opts: LogoutOptions = {}): Promise<void> => {
      await client.logout(opts);
      if (opts.openUrl || opts.openUrl === false) {
        dispatch({ type: 'LOGOUT' });
      }
    },
    [client]
  );

  const getAccessTokenSilently = useCallback(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    async (opts?: GetTokenSilentlyOptions): Promise<any> => {
      let token;
      try {
        token = await client.getTokenSilently(opts);
      } catch (error) {
        throw tokenError(error);
      } finally {
        dispatch({
          type: 'GET_ACCESS_TOKEN_COMPLETE',
          user: await client.getUser(),
        });
      }
      return token;
    },
    [client]
  );

  const getAccessTokenWithPopup = useCallback(
    async (
      opts?: GetTokenWithPopupOptions,
      config?: PopupConfigOptions
    ): Promise<string | undefined> => {
      let token;
      try {
        token = await client.getTokenWithPopup(opts, config);
      } catch (error) {
        throw tokenError(error);
      } finally {
        dispatch({
          type: 'GET_ACCESS_TOKEN_COMPLETE',
          user: await client.getUser(),
        });
      }
      return token;
    },
    [client]
  );

  const connectAccountWithRedirect = useCallback(
    (options: RedirectConnectAccountOptions) =>
      client.connectAccountWithRedirect(options),
    [client]
  );

  const getIdTokenClaims = useCallback(
    () => client.getIdTokenClaims(),
    [client]
  );

  const exchangeToken = useCallback(
    async (
      options: CustomTokenExchangeOptions
    ): Promise<TokenEndpointResponse> => {
      let tokenResponse;
      try {
        tokenResponse = await client.exchangeToken(options);
      } catch (error) {
        throw tokenError(error);
      } finally {
        // We dispatch the standard GET_ACCESS_TOKEN_COMPLETE action here to maintain 
        // backward compatibility and consistency with the getAccessTokenSilently flow. 
        // This ensures the SDK's internal state lifecycle (loading/user updates) remains 
        // identical regardless of whether the token was retrieved via silent auth or CTE.
        dispatch({
          type: 'GET_ACCESS_TOKEN_COMPLETE',
          user: await client.getUser(),
        });
      }
      return tokenResponse;
    },
    [client]
  );

  const handleRedirectCallback = useCallback(
    async (
      url?: string
    ): Promise<RedirectLoginResult | ConnectAccountRedirectResult> => {
      try {
        return await client.handleRedirectCallback(url);
      } catch (error) {
        throw tokenError(error);
      } finally {
        dispatch({
          type: 'HANDLE_REDIRECT_COMPLETE',
          user: await client.getUser(),
        });
      }
    },
    [client]
  );

  const getDpopNonce = useCallback<Auth0Client['getDpopNonce']>(
    (id) => client.getDpopNonce(id),
    [client]
  );

  const setDpopNonce = useCallback<Auth0Client['setDpopNonce']>(
    (nonce, id) => client.setDpopNonce(nonce, id),
    [client]
  );

  const generateDpopProof = useCallback<Auth0Client['generateDpopProof']>(
    (params) => client.generateDpopProof(params),
    [client]
  );

  const createFetcher = useCallback<Auth0Client['createFetcher']>(
    (config) => client.createFetcher(config),
    [client]
  );

  const getConfiguration = useCallback<Auth0Client['getConfiguration']>(
    () => client.getConfiguration(),
    [client]
  );

  const contextValue = useMemo<Auth0ContextInterface<TUser>>(() => {
    return {
      ...state,
      getAccessTokenSilently,
      getAccessTokenWithPopup,
      getIdTokenClaims,
      exchangeToken,
      loginWithRedirect,
      loginWithPopup,
      connectAccountWithRedirect,
      logout,
      handleRedirectCallback,
      getDpopNonce,
      setDpopNonce,
      generateDpopProof,
      createFetcher,
      getConfiguration,
    };
  }, [
    state,
    getAccessTokenSilently,
    getAccessTokenWithPopup,
    getIdTokenClaims,
    exchangeToken,
    loginWithRedirect,
    loginWithPopup,
    connectAccountWithRedirect,
    logout,
    handleRedirectCallback,
    getDpopNonce,
    setDpopNonce,
    generateDpopProof,
    createFetcher,
    getConfiguration,
  ]);

  return <context.Provider value={contextValue}>{children}</context.Provider>;
};

export default Auth0Provider;
