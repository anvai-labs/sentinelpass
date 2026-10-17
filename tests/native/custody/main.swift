// Host Swift/C ABI probe. No keystore, app entitlement or hardware qualification.
import Foundation

func validate(_ bytes: Data, kind: UInt32) -> SPErrorCode {
    bytes.withUnsafeBytes { raw in
        sp_custody_validate_metadata(2, kind, raw.baseAddress?.assumingMemoryBound(to: UInt8.self), UInt(raw.count))
    }
}
let root = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
let scopeBytes = try Data(contentsOf: root.appendingPathComponent("scope.golden.json"))
let referenceBytes = try Data(contentsOf: root.appendingPathComponent("reference.golden.json"))
let decoder = JSONDecoder()
let scope = try decoder.decode(CustodyScope.self, from: scopeBytes)
let reference = try decoder.decode(ObjectRef.self, from: referenceBytes)
precondition(validate(scopeBytes, kind: 1) == SPErrorCode_Success)
precondition(validate(referenceBytes, kind: 2) == SPErrorCode_Success)
let scopeRoundtrip = try JSONEncoder().encode(scope)
let referenceRoundtrip = try JSONEncoder().encode(reference)
precondition(validate(scopeRoundtrip, kind: 1) == SPErrorCode_Success)
precondition(validate(referenceRoundtrip, kind: 2) == SPErrorCode_Success)
precondition(validate(referenceBytes, kind: 1) == SPErrorCode_InvalidParam)
var info = SPBridgeInfo()
precondition(sp_bridge_negotiate(2, &info) == SPErrorCode_Success)
precondition(info.feature_flags & CustodyContract.feature == 0)
precondition(sp_bridge_negotiate(3, &info) == SPErrorCode_AbiUnsupported)
print("custody metadata host Swift/C: 8 checks passed")
