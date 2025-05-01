import type { wechatAuthPlugin } from ".";
import type { BetterAuthClientPlugin } from "../../types";

export const wechatAuthClient = () => {
	return {
		id: "wechat-custom-client",
		$InferServerPlugin: {} as ReturnType<typeof wechatAuthPlugin>,
	} satisfies BetterAuthClientPlugin;
};