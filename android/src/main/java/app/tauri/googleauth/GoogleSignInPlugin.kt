package app.tauri.googleauth

import android.app.Activity
import android.util.Log
import android.webkit.WebView
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

@InvokeArg
class SignInArgs {
    lateinit var clientId: String
}

@TauriPlugin
class GoogleSignInPlugin(private val activity: Activity) : Plugin(activity) {
    
    companion object {
        private const val TAG = "GoogleSignInPlugin"
    }
    
    private val scope = CoroutineScope(Dispatchers.Main)
    private lateinit var authManager: GoogleAuthManager
    
    override fun load(webView: WebView) {
        super.load(webView)
        authManager = GoogleAuthManager(activity)
    }
    
    @Command
    fun signIn(invoke: Invoke) {
        scope.launch {
            try {
                val args = invoke.parseArgs(SignInArgs::class.java)
                
                if (args.clientId.isEmpty()) {
                    invoke.reject("Client ID is required")
                    return@launch
                }
                
                Log.d(TAG, "Signing in with client ID: ${args.clientId}")
                
                val result = authManager.login(args.clientId)
                resolveResult(invoke, result)
            } catch (e: Exception) {
                Log.e(TAG, "Google login failed", e)
                invoke.reject("Google login failed: ${e.message}")
            }
        }
    }

    private fun resolveResult(invoke: Invoke, result: GoogleAuthResult) {
        val response = JSObject().apply {
            put("idToken", result.idToken)
            put("nonce", result.nonce)
        }
        invoke.resolve(response)
    }
}
