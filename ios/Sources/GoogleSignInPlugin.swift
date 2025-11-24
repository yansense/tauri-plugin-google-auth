import SimpleGoogleSignIn
import Tauri
import UIKit
import WebKit
import Foundation

class SignInArgs: Decodable {
    let clientId: String
    let serverClientId: String?
    let scopes: [String]?
    let hostedDomain: String?
    let loginHint: String?
}

class SignOutArgs: Decodable {
    let accessToken: String?
}

class RefreshTokenArgs: Decodable {
    let refreshToken: String
}

class GoogleSignInPlugin: Plugin {
    @objc public func signIn(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(SignInArgs.self)

        DispatchQueue.main.async { [weak self] in
            guard let rootViewController = self?.manager.viewController else {
                invoke.reject("No root view controller found")
                return
            }

            guard let scopes = args.scopes, !scopes.isEmpty else {
                invoke.reject("No scopes found")
                return
            }

            // 生成 nonce (UUID 格式)
            let nonce = UUID().uuidString

            let configuration: GoogleSignInConfiguration
            if let serverClientId = args.serverClientId {
                configuration = GoogleSignInConfiguration(
                    clientID: args.clientId,
                    serverClientID: serverClientId
                )
            } else {
                configuration = GoogleSignInConfiguration(
                    clientID: args.clientId
                )
            }

            SimpleGoogleSignIn.shared.configure(configuration: configuration)

            SimpleGoogleSignIn.shared.signIn(
                presentingViewController: rootViewController,
                nonce: nonce,  // 传递我们生成的 nonce
                scopes: scopes
            ) { result in
                DispatchQueue.main.async {
                    switch result {
                    case .success(let signInResult):
                        // 使用明确的类型构建字典
                        var tokenDict = [String: Any]()
                        
                        // 必填字段
                        tokenDict["accessToken"] = signInResult.accessToken.tokenString as String
                        tokenDict["scopes"] = signInResult.grantedScopes ?? [] as [String]
                        
                        // 可选字段 - refreshToken
                        if let refreshToken = signInResult.refreshToken {
                            tokenDict["refreshToken"] = refreshToken as String
                        } else {
                            tokenDict["refreshToken"] = "" as String
                        }

                        // 可选字段 - idToken
                        if let idToken = signInResult.openIdToken {
                            tokenDict["idToken"] = idToken as String
                        }

                        // 可选字段 - nonce (关键!)
                        if let returnedNonce = signInResult.nonce {
                            tokenDict["nonce"] = returnedNonce as String
                        }

                        // 可选字段 - expiresAt
                        if let expirationDate = signInResult.accessToken.expirationDate {
                            tokenDict["expiresAt"] = Int64(expirationDate.timeIntervalSince1970 * 1000) as Int64
                        }

                        invoke.resolve(tokenDict)

                    case .failure(let error):
                        invoke.reject(error.localizedDescription)
                    }
                }
            }
        }
    }

    @objc public func signOut(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(SignOutArgs.self)

        DispatchQueue.main.async {
            SimpleGoogleSignIn.shared.signOut(accessToken: args.accessToken) { _ in
                invoke.resolve(["success": true])
            }
        }
    }

    @objc public func refreshToken(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(RefreshTokenArgs.self)
        
         DispatchQueue.main.async {
             SimpleGoogleSignIn.shared.refreshTokens(refreshToken: args.refreshToken) { result in
                 switch result {
                 case .success(let signInResult):
                     var tokenDict: [String: Any] = [
                         "idToken": signInResult.openIdToken,
                         "accessToken": signInResult.accessToken.tokenString,
                         "refreshToken": signInResult.refreshToken ?? "",
                         "scopes": signInResult.grantedScopes ?? []
                     ]

                      if let expirationDate = signInResult.accessToken.expirationDate {
                          tokenDict["expiresAt"] = Int64(expirationDate.timeIntervalSince1970 * 1000)
                      }

                     invoke.resolve(tokenDict)

                 case .failure(let error):
                     invoke.reject(error.localizedDescription)
                 }
             }
         }
    }

    @objc public func handleUrl(_ url: URL) -> Bool {
        return SimpleGoogleSignIn.shared.handleURL(url)
    }
}

@_cdecl("init_plugin_google_auth")
func initPlugin() -> Plugin {
    return GoogleSignInPlugin()
}
