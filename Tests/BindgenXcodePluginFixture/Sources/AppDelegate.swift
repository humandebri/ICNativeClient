import ICNativeClient
import UIKit

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {
    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        _ = ManagementCanister.self
        _ = ManagementCanisterStatusArgs.self
        _ = ManagementCanisterStatus.self
        return true
    }
}
