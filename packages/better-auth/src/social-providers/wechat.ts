/**
 * <div class="provider" style={{backgroundColor: "#24292f", display: "flex", justifyContent: "space-between", color: "#fff", padding: 16}}>
 * <span>Built-in <b>WeChat</b> integration.</span>
 * <a href="https://www.wechat.com/">
 *   <img style={{display: "block"}} src="https://authjs.dev/img/providers/wechat.svg" height="48" width="48"/>
 * </a>
 * </div>
 *
 * @module providers/wechat
 */
import { betterFetch } from "@better-fetch/fetch"; // Correct import based on github.ts
import type { OAuthProvider, ProviderOptions, OAuth2Tokens } from "../oauth2"; // Adjusted import

/** @see [Get the authenticated user](https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Authorized_Interface_Calling_UnionID.html) */
export interface WeChatProfile {
  openid: string
  nickname: string
  sex: number
  province: string
  city: string
  country: string
  headimgurl: string
  privilege: string[]
  unionid: string
  [claim: string]: unknown
}

// Define WeChat specific options extending the base ProviderOptions
export interface WeChatOptions extends ProviderOptions<WeChatProfile> {
  platformType?: "OfficialAccount" | "WebsiteApp";
  disableDefaultScope?: boolean;
}

export const wechat = (options: WeChatOptions): OAuthProvider<WeChatProfile> => {
  const platformType = options.platformType ?? "OfficialAccount";
  const authorizationEndpoint =
    platformType === "OfficialAccount"
      ? "https://open.weixin.qq.com/connect/oauth2/authorize"
      : "https://open.weixin.qq.com/connect/qrconnect";
  const tokenEndpoint = "https://api.weixin.qq.com/sns/oauth2/access_token";
  const userInfoEndpoint = "https://api.weixin.qq.com/sns/userinfo";

  return {
    id: "wechat",
    name: "WeChat",
    createAuthorizationURL({ state, scopes, redirectURI }) {
      // WeChat uses 'appid' instead of 'client_id'
      // WeChat uses different scopes based on platformType
      const defaultScopes = platformType === "OfficialAccount" ? ["snsapi_userinfo"] : ["snsapi_login"];
      const _scopes = options.disableDefaultScope ? [] : defaultScopes;
      options.scope?.forEach(s => !_scopes.includes(s) && _scopes.push(s));
      scopes?.forEach(s => !_scopes.includes(s) && _scopes.push(s));

      const url = new URL(authorizationEndpoint);
      url.searchParams.set("appid", options.clientId);
      url.searchParams.set("redirect_uri", redirectURI);
      url.searchParams.set("response_type", "code");
      url.searchParams.set("scope", _scopes.join(","));
      url.searchParams.set("state", state);
      if (platformType === "WebsiteApp") {
         // WebsiteApp might need specific params, add if necessary
         // url.searchParams.set("some_param", "value");
      }
      url.hash = "wechat_redirect"; // Required by WeChat docs
      return url;
    },
    async validateAuthorizationCode({ code }): Promise<OAuth2Tokens> { // Removed redirectURI as it's not used by WeChat token endpoint
      // WeChat uses 'appid' and 'secret' instead of client_id/client_secret in params
      const url = new URL(tokenEndpoint);
      url.searchParams.set("appid", options.clientId);
      url.searchParams.set("secret", options.clientSecret);
      url.searchParams.set("code", code);
      url.searchParams.set("grant_type", "authorization_code");

      // Use betterFetch, check error and data.errcode for issues
      const { data, error } = await betterFetch<any>(url.toString(), {
         method: "GET", // WeChat token endpoint uses GET
         // No parser option needed, betterFetch handles JSON by default
      });

      // Check for errors reported by betterFetch or WeChat API
      if (error || data?.errcode) {
        const errorMessage = data?.errmsg || error?.message || "Failed to fetch WeChat token";
        console.error("WeChat Token Error:", error || data);
        throw new Error(errorMessage);
      }

      // Adapt WeChat response to OAuth2Tokens interface
      const tokens: OAuth2Tokens & { openid?: string; unionid?: string } = {
        accessToken: data.access_token,
        tokenType: "bearer", // Assume bearer
        refreshToken: data.refresh_token,
        accessTokenExpiresAt: data.expires_in ? new Date(Date.now() + data.expires_in * 1000) : undefined,
        scopes: data.scope?.split(" "),
        openid: data.openid, // Store openid needed for userinfo request
        unionid: data.unionid, // Store unionid if available
      };
      return tokens;
    },
    async getUserInfo(tokens: OAuth2Tokens & { openid?: string; unionid?: string }): Promise<{ user: { id: string; name?: string; email?: string | null; image?: string; emailVerified: boolean; }; data: WeChatProfile; } | null> {
       // Allow overriding via options
       if (options.getUserInfo) {
         // Ensure the custom getUserInfo function receives the necessary tokens (including openid)
         return options.getUserInfo(tokens);
       }

       const openid = tokens.openid;
       const accessToken = tokens.accessToken;

       if (!openid || !accessToken) {
         console.error("WeChat UserInfo Error: Missing openid or accessToken in token object", tokens);
         throw new Error("OpenID or Access Token missing");
       }

       const url = new URL(userInfoEndpoint);
       url.searchParams.set("access_token", accessToken);
       url.searchParams.set("openid", openid);
       url.searchParams.set("lang", "zh_CN"); // Request Chinese language

       const { data: profile, error } = await betterFetch<WeChatProfile>(url.toString(), {
         method: "GET",
         // No parser option needed
       });

       // Check for errors reported by betterFetch or WeChat API
       if (error || profile?.errcode) {
         // Ensure errorMessage is explicitly treated as a string for the Error constructor
         const errorMessage = String(profile?.errmsg || error?.message || "Failed to fetch WeChat user info");
         console.error("WeChat UserInfo Fetch Error:", error || profile);
         throw new Error(errorMessage);
       }

       // Use unionid as primary ID if available, otherwise fallback to openid
       const userId = profile.unionid ?? profile.openid;
       if (!userId) {
           console.error("WeChat UserInfo Error: Missing unionid and openid in profile", profile);
           throw new Error("Could not determine user ID from WeChat profile");
       }

       const userMap = await options.mapProfileToUser?.(profile);

       return {
         user: {
           id: userId,
           name: profile.nickname,
           email: null, // WeChat does not provide email
           image: profile.headimgurl,
           emailVerified: false, // No email, so not verified
           ...userMap, // Apply custom mapping
         },
         data: profile, // Raw profile data
       };
    },
    // Optional: Implement refreshAccessToken if needed and supported by WeChat API for your platformType
    // async refreshAccessToken(refreshToken: string): Promise<OAuth2Tokens> { ... }
  } satisfies OAuthProvider<WeChatProfile>;
};