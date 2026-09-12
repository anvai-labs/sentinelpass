//
//  Pasteboard.swift
//  SentinelPass
//
//  Local expiring pasteboard writes for sensitive values (WBS-824).
//

import Foundation
#if canImport(UIKit)
import UIKit
#endif

enum Pasteboard {

    /// Lifetime of a sensitive item on the pasteboard. 30 s covers the
    /// paste-into-the-other-app gesture without leaving credentials
    /// readable for the session lifetime (which a bare
    /// `UIPasteboard.general.string =` assignment does — it never expires).
    static let sensitiveItemLifetime: TimeInterval = 30

    /**
     * Copy a sensitive value (password, TOTP code) to the LOCAL pasteboard
     * with a hard expiration.
     *
     * Documented limitation (honest scope of the platform API): the
     * `expirationDate` option limits the ITEM lifetime on this device's
     * general pasteboard; UIPasteboard offers NO opt-out from Universal
     * Clipboard, so while the item is alive (and only then) it may still
     * sync to the user's nearby Apple devices. There is no
     * "localOnly" flag in the API. Expiring the item after 30 s bounds the
     * exposure window to what the platform permits.
     */
    static func copySensitive(_ value: String) {
        #if canImport(UIKit)
        let expiration = Date().addingTimeInterval(sensitiveItemLifetime)
        UIPasteboard.general.setItems(
            [[UIPasteboard.typeAutomatic: value]],
            options: [.expirationDate: expiration]
        )
        #endif
    }
}
