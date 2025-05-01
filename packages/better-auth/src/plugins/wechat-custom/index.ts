import { betterFetch } from '@better-fetch/fetch';
import { APIError } from 'better-call';
import { createAuthEndpoint } from '../../api'; // 重新导入 createAuthEndpoint
import type {
  BetterAuthPlugin,
  BetterAuthOptions,
  User,
  Account,
  AuthContext,
  GenericEndpointContext,
} from '../../types';
// 移除 OAuth2Tokens 导入
import { URL, URLSearchParams } from 'node:url';
import { parseState } from '../../oauth2';
import { handleOAuthUserInfo } from '../../oauth2/link-account';
import { setSessionCookie } from '../../cookies';
import { generateRandomString } from '../../crypto';
import { z } from 'zod';

// --- 本地类型定义 ---
interface ParsedStateData {
  callbackURL: string;
  codeVerifier?: string;
  errorURL?: string;
  newUserURL?: string;
  expiresAt: number;
  link?: {
    email: string;
    userId: string;
  };
  requestSignUp?: boolean;
  providerId?: string;
}

// --- Configuration Options ---
export interface WechatCustomPluginOptions {
  clientId: string;
  clientSecret: string;
  scope?: string;
  disableSignUp?: boolean;
  overrideUserInfo?: boolean;
}

// --- WeChat API Response Types ---
interface WechatErrorResponse {
  errcode: number;
  errmsg: string;
}

interface WechatTokenResponse extends Partial<WechatErrorResponse> {
  access_token: string;
  expires_in: number;
  refresh_token?: string;
  openid: string;
  scope?: string;
  unionid?: string;
}

interface WechatUserInfoResponse extends Partial<WechatErrorResponse> {
  openid: string;
  nickname: string;
  sex: number;
  province: string;
  city: string;
  country: string;
  headimgurl: string;
  privilege: string[];
  unionid?: string;
}

// --- Zod Schemas ---
const signInBodySchema = z.object({
    callbackUrl: z.string().url().optional(),
    errorUrl: z.string().url().optional(),
    newUserUrl: z.string().url().optional(),
}).optional();

const callbackQuerySchema = z.object({
    code: z.string().optional(),
    state: z.string().optional(),
    error: z.string().optional(),
    error_description: z.string().optional(),
});


// --- WeChat Custom Plugin ---
export const wechatAuthPlugin = (
  pluginOptions: WechatCustomPluginOptions,
): BetterAuthPlugin => {
  const {
    clientId,
    clientSecret,
    scope = 'snsapi_login',
    disableSignUp = false,
    overrideUserInfo = false,
  } = pluginOptions;

  if (!clientId || !clientSecret) {
    throw new Error(
      'WechatCustomPlugin: clientId (appid) and clientSecret are required.',
    );
  }

  const WECHAT_AUTHORIZE_URL = 'https://open.weixin.qq.com/connect/qrconnect';
  const WECHAT_TOKEN_URL = 'https://api.weixin.qq.com/sns/oauth2/access_token';
  const WECHAT_USERINFO_URL = 'https://api.weixin.qq.com/sns/userinfo';
  const PROVIDER_ID = 'wechat-custom';

  return {
    id: PROVIDER_ID,

    init: (ctx: AuthContext) => {
      ctx.logger.info(`[BetterAuth] Initializing ${PROVIDER_ID} plugin with clientId: ${clientId.substring(0, 4)}...`);
    },

    // 使用 createAuthEndpoint 定义 endpoints
    endpoints: {
      wechatCustomSignIn: createAuthEndpoint( // 使用 createAuthEndpoint
        `/sign-in/${PROVIDER_ID}`, // path
        { // options
          method: "POST",
          body: signInBodySchema, // schema for body
        },
        async (c: GenericEndpointContext) => { // handler
          const { options: handlerOptions, internalAdapter, baseURL, body } = c.context;

          const callbackURL = body?.callbackUrl ?? `${baseURL}/`;
          const errorURL = body?.errorUrl ?? `${baseURL}/sign-in?error=OAuthSignin&provider=${PROVIDER_ID}`;
          const newUserURL = body?.newUserUrl ?? callbackURL;

          const state = generateRandomString(32);
          const stateValue = JSON.stringify({
            providerId: PROVIDER_ID,
            callbackURL,
            errorURL,
            newUserURL,
            expiresAt: Date.now() + 10 * 60 * 1000,
          });
          const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
          await internalAdapter.createVerificationValue({
            value: stateValue,
            identifier: state,
            expiresAt,
          });

          const callbackPath = `${handlerOptions.basePath ?? ''}/oauth2/callback/${PROVIDER_ID}`;
          const redirectUri = new URL(callbackPath, baseURL).toString();

          const authorizationUrl = new URL(WECHAT_AUTHORIZE_URL);
          authorizationUrl.searchParams.set('appid', clientId);
          authorizationUrl.searchParams.set('redirect_uri', redirectUri);
          authorizationUrl.searchParams.set('response_type', 'code');
          authorizationUrl.searchParams.set('scope', scope);
          authorizationUrl.searchParams.set('state', state);
          const finalUrl = `${authorizationUrl.toString()}#wechat_redirect`;

          c.context.logger.info(`[BetterAuth] [${PROVIDER_ID}] Redirecting to WeChat authorization: ${finalUrl}`);
          throw c.redirect(finalUrl);
        }
      ),

      wechatCustomCallback: createAuthEndpoint( // 使用 createAuthEndpoint
        `/oauth2/callback/${PROVIDER_ID}`, // path
        { // options
          method: "GET",
          query: callbackQuerySchema, // schema for query
        },
        async (c: GenericEndpointContext): Promise<void> => { // handler
          const { options: handlerOptions, internalAdapter, logger, baseURL } = c.context;
          const query = c.query as z.infer<typeof callbackQuerySchema>; // 类型来自 schema

          logger.info(`[BetterAuth] [${PROVIDER_ID}] Received callback from WeChat with query:`, query);

          let stateData: ParsedStateData | null = null;
          let defaultErrorURL = `${baseURL}/sign-in?error=OAuthCallback&provider=${PROVIDER_ID}`;

          try {
            if (query.error) {
              logger.error(`[BetterAuth] [${PROVIDER_ID}] WeChat callback error: ${query.error} - ${query.error_description}`);
              let specificErrorURL = defaultErrorURL;
              if (query.state) {
                try {
                  stateData = await parseState(c) as ParsedStateData;
                  if (stateData?.errorURL) specificErrorURL = stateData.errorURL;
                } catch (stateError: any) {
                  logger.warn(`[BetterAuth] [${PROVIDER_ID}] Failed to parse state during error handling: ${stateError.message}`);
                }
              }
              const params = new URLSearchParams({
                  error: query.error,
                  error_description: query.error_description ?? 'WeChat authorization failed.',
              });
              throw c.redirect(`${specificErrorURL}${specificErrorURL.includes('?') ? '&' : '?'}${params.toString()}`);
            }

            if (!query.code || !query.state) {
              throw new APIError("BAD_REQUEST", { message: 'Missing code or state from WeChat callback' });
            }

            stateData = await parseState(c) as ParsedStateData;
            if (!stateData) {
              throw new APIError("BAD_REQUEST", { message: 'Invalid or expired state parameter.' });
            }
            const errorURL = stateData.errorURL || defaultErrorURL;

            const { code } = query;

            // --- 2. Exchange Code for Access Token ---
            const tokenUrl = new URL(WECHAT_TOKEN_URL);
            tokenUrl.searchParams.set('appid', clientId);
            tokenUrl.searchParams.set('secret', clientSecret);
            tokenUrl.searchParams.set('code', code);
            tokenUrl.searchParams.set('grant_type', 'authorization_code');

            logger.info(`[BetterAuth] [${PROVIDER_ID}] Requesting WeChat token from: ${tokenUrl.toString()}`);
            let tokenResponse: WechatTokenResponse;
            try {
                 const fetchResult = await betterFetch<{ data?: Partial<WechatTokenResponse>, error?: any }>(
                    tokenUrl.toString(),
                    { method: 'GET' },
                );
                 if (fetchResult && typeof fetchResult === 'object' && 'data' in fetchResult && fetchResult.data) {
                    tokenResponse = fetchResult.data as WechatTokenResponse;
                    if (!tokenResponse.access_token || !tokenResponse.openid) {
                        logger.error(`[BetterAuth] [${PROVIDER_ID}] Token response data missing required fields:`, tokenResponse);
                        throw new APIError("INTERNAL_SERVER_ERROR", { message: 'Invalid token response data from WeChat' });
                    }
                 } else if (fetchResult && typeof fetchResult === 'object' && 'error' in fetchResult) {
                    throw new APIError("INTERNAL_SERVER_ERROR", { message: 'Failed to fetch WeChat token (API Error)', cause: fetchResult.error });
                 } else {
                    logger.error(`[BetterAuth] [${PROVIDER_ID}] Unexpected token response structure or empty data:`, fetchResult);
                    throw new APIError("INTERNAL_SERVER_ERROR", { message: 'Unexpected response structure from WeChat token endpoint' });
                 }
            } catch (fetchError: any) {
                 logger.error(`[BetterAuth] [${PROVIDER_ID}] Fetch Token Network/HTTP Error:`, fetchError);
                 throw new APIError("INTERNAL_SERVER_ERROR", { message: 'Failed to communicate with WeChat token endpoint', cause: fetchError });
            }


            if (tokenResponse?.errcode) {
              logger.error(`[BetterAuth] [${PROVIDER_ID}] WeChat Token API Error: ${tokenResponse.errcode} - ${tokenResponse.errmsg}`);
              throw new APIError("INTERNAL_SERVER_ERROR", {
                  message: `Failed to retrieve WeChat access token: ${tokenResponse.errmsg}`,
                  cause: { providerError: { errcode: tokenResponse.errcode, errmsg: tokenResponse.errmsg } }
              });
            }

            const { access_token, openid, unionid: tokenUnionId, expires_in, refresh_token, scope } = tokenResponse;
            logger.info(`[BetterAuth] [${PROVIDER_ID}] Received WeChat token for openid: ${openid}, unionid: ${tokenUnionId}`);

            // --- 3. Fetch User Information ---
            const userInfoUrl = new URL(WECHAT_USERINFO_URL);
            userInfoUrl.searchParams.set('access_token', access_token);
            userInfoUrl.searchParams.set('openid', openid);
            userInfoUrl.searchParams.set('lang', 'zh_CN');

            logger.info(`[BetterAuth] [${PROVIDER_ID}] Requesting WeChat user info from: ${userInfoUrl.toString()}`);
            let userInfoResponse: WechatUserInfoResponse;
             try {
                const fetchResult = await betterFetch<{ data?: Partial<WechatUserInfoResponse>, error?: any }>(
                    userInfoUrl.toString(),
                    { method: 'GET' },
                );
                 if (fetchResult && typeof fetchResult === 'object' && 'data' in fetchResult && fetchResult.data) {
                    userInfoResponse = fetchResult.data as WechatUserInfoResponse;
                    if (!userInfoResponse.openid) {
                        logger.error(`[BetterAuth] [${PROVIDER_ID}] User info response data missing required fields:`, userInfoResponse);
                        throw new APIError("INTERNAL_SERVER_ERROR", { message: 'Invalid user info response data from WeChat' });
                    }
                 } else if (fetchResult && typeof fetchResult === 'object' && 'error' in fetchResult) {
                    throw new APIError("INTERNAL_SERVER_ERROR", { message: 'Failed to fetch WeChat user info (API Error)', cause: fetchResult.error });
                 } else {
                    logger.error(`[BetterAuth] [${PROVIDER_ID}] Unexpected user info response structure or empty data:`, fetchResult);
                    throw new APIError("INTERNAL_SERVER_ERROR", { message: 'Unexpected response structure from WeChat user info endpoint' });
                 }
            } catch (fetchError: any) {
                 logger.error(`[BetterAuth] [${PROVIDER_ID}] Fetch UserInfo Network/HTTP Error:`, fetchError);
                 throw new APIError("INTERNAL_SERVER_ERROR", { message: 'Failed to communicate with WeChat userinfo endpoint', cause: fetchError });
            }

            if (userInfoResponse?.errcode) {
              logger.error(`[BetterAuth] [${PROVIDER_ID}] WeChat UserInfo API Error: ${userInfoResponse.errcode} - ${userInfoResponse.errmsg}`);
               throw new APIError("INTERNAL_SERVER_ERROR", {
                  message: `Failed to retrieve WeChat user info: ${userInfoResponse.errmsg}`,
                  cause: { providerError: { errcode: userInfoResponse.errcode, errmsg: userInfoResponse.errmsg } }
              });
            }

            logger.info(`[BetterAuth] [${PROVIDER_ID}] Received WeChat User Info:`, { openid: userInfoResponse.openid, nickname: userInfoResponse.nickname, unionid: userInfoResponse.unionid });

            // --- 4. Determine Unique User ID ---
            const userId = userInfoResponse.unionid || tokenUnionId || openid;
            if (!userId) {
                logger.error(`[BetterAuth] [${PROVIDER_ID}] Could not determine a unique user ID.`);
                throw new APIError("INTERNAL_SERVER_ERROR", { message: 'Unable to determine user identifier from WeChat.' });
            }
            const idSource = userInfoResponse.unionid ? 'UserInfo UnionID' : tokenUnionId ? 'Token UnionID' : 'OpenID';
            logger.info(`[BetterAuth] [${PROVIDER_ID}] Determined user ID: ${userId} (Source: ${idSource})`);

            // --- 5. Map WeChat User Info ---
            const placeholderEmail = `${userId}@wechat.placeholder.auth`;
            const mappedUser: Omit<User, "createdAt" | "updatedAt"> = {
              id: userId,
              name: userInfoResponse.nickname || `WeChat User ${userId.substring(0, 6)}`,
              image: userInfoResponse.headimgurl || null,
              email: placeholderEmail,
              emailVerified: false,
            };

            // --- 6. Prepare Account Data (Mapping fields) ---
            const accountData: Omit<Account, "id" | "userId" | "createdAt" | "updatedAt"> = {
              providerId: PROVIDER_ID,
              accountId: userId,
              accessToken: access_token,
              refreshToken: refresh_token || null,
              accessTokenExpiresAt: expires_in ? new Date(Date.now() + expires_in * 1000) : null,
              scope: scope || null,
            };

            // --- 7. Handle User Sign-in/Sign-up ---
            const result = await handleOAuthUserInfo(c, {
              userInfo: mappedUser,
              account: accountData,
              callbackURL: stateData.callbackURL,
              disableSignUp: disableSignUp,
              overrideUserInfo: overrideUserInfo,
            });

            // --- 8. Process the Result ---
            if (result.error) {
              logger.error(`[BetterAuth] [${PROVIDER_ID}] handleOAuthUserInfo error: ${result.error}`);
              throw new APIError("INTERNAL_SERVER_ERROR", { message: `User handling failed: ${result.error}` });
            }

            if (!result.data) {
                 logger.error(`[BetterAuth] [${PROVIDER_ID}] handleOAuthUserInfo did not return data on success.`);
                 throw new APIError("INTERNAL_SERVER_ERROR", { message: 'Authentication process failed internally after user handling.' });
            }

            const { session, user } = result.data;
            const isRegister = result.isRegister;

            // --- 9. Set Session Cookie ---
            await setSessionCookie(c, { session, user });
            logger.info(`[BetterAuth] [${PROVIDER_ID}] Session cookie set for user: ${user.id}`);

            // --- 10. Determine Final Redirect URL ---
            let redirectUrl = stateData.callbackURL;
            if (isRegister && stateData.newUserURL) {
              redirectUrl = stateData.newUserURL;
              logger.info(`[BetterAuth] [${PROVIDER_ID}] New user registered, redirecting to newUserURL: ${redirectUrl}`);
            } else {
               logger.info(`[BetterAuth] [${PROVIDER_ID}] User signed in, redirecting to callbackURL: ${redirectUrl}`);
            }

            throw c.redirect(redirectUrl);

          } catch (error: any) {
            // --- Centralized Error Handling ---
            logger.error(`[BetterAuth] [${PROVIDER_ID}] Callback Handler Error:`, error);

            if (error instanceof APIError && error.status === "FOUND") {
                throw error;
            }

            const finalErrorURL = stateData?.errorURL || defaultErrorURL;
            const params = new URLSearchParams();
            if (error instanceof APIError) {
                params.set('error', String(error.status ?? 'OAuthCallbackError'));
                params.set('error_description', error.message);
                if (error.cause && typeof error.cause === 'object' && 'providerError' in error.cause) {
                    const providerError = error.cause.providerError as Partial<WechatErrorResponse>;
                    if (providerError && typeof providerError === 'object') {
                        params.set('provider_error_code', String(providerError.errcode ?? 'UNKNOWN'));
                        params.set('provider_error_message', providerError.errmsg ?? 'Unknown provider error');
                    }
                }
            } else {
                params.set('error', 'OAuthCallbackError');
                params.set('error_description', error.message || 'An unexpected error occurred during WeChat sign-in.');
            }

            throw c.redirect(`${finalErrorURL}${finalErrorURL.includes('?') ? '&' : '?'}${params.toString()}`);
          }
        }
      ),
    },
  };
};