import type { CapacitorConfig } from "@capacitor/cli";

const config: CapacitorConfig = {
  appId: "tech.atlasnexus.ai2work",
  appName: "AI2Work",
  webDir: "www",
  server: {
    url: "https://ai2work.onrender.com",
    cleartext: false,
  },
  android: {
    allowMixedContent: true,
    webContentsDebuggingEnabled: false,
    // Celo MiniPay / Opera Mini compatibility
    // MiniPay injects window.ethereum — no MetaMask SDK needed
    overrideUserAgent: "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Mobile Safari/537.36",
  },
  plugins: {
    SplashScreen: {
      launchShowDuration: 0,
      launchAutoHide: true,
      backgroundColor: "#0B1120",
      showSpinner: false,
    },
  },
  includePlugins: ["NativeEthWallet"],
};

export default config;
