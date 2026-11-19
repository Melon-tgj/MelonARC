import XCTest

/// The address parser is the one place a token could be sent somewhere it does not
/// belong, so it is tested against the shapes that look like loopback and are not.
final class APIAddressTests: XCTestCase {
    func testALiteralLoopbackAddressIsAccepted() throws {
        let address = try APIAddress.parse("127.0.0.1:7946")
        XCTAssertEqual(address.host, "127.0.0.1")
        XCTAssertEqual(address.port, 7946)
        XCTAssertEqual(address.label, "127.0.0.1:7946")
        XCTAssertEqual(address.baseURL?.absoluteString, "http://127.0.0.1:7946/")
    }

    func testTheWholeLoopbackRangeIsAccepted() throws {
        for host in ["127.0.0.1", "127.1.2.3", "127.255.255.254"] {
            XCTAssertNoThrow(try APIAddress.parse("\(host):8080"), "\(host) is loopback")
        }
    }

    func testLocalHostIsMappedToTheIPv4Literal() throws {
        let address = try APIAddress.parse("localhost:7946")
        XCTAssertEqual(address.host, "127.0.0.1")
    }

    func testBracketedIPv6IsRefusedBecauseOnlyIPv4LoopbackHasAnATSException() {
        XCTAssertThrowsError(try APIAddress.parse("[::1]:7946")) { error in
            guard case ShellError.invalidAddress = error else {
                return XCTFail("[::1] failed with \(error) instead of an address error")
            }
        }
    }

    func testSurroundingWhitespaceIsIgnored() throws {
        XCTAssertEqual(try APIAddress.parse("  127.0.0.1:7946\n").port, 7946)
    }

    func testAddressesThatOnlyLookLikeLoopbackAreRefused() {
        let refused = [
            "0.0.0.0:7946",
            "10.0.0.1:7946",
            "192.168.1.1:7946",
            "127.example.com:7946",
            "example.com:7946",
            "localhost.example.com:7946",
        ]
        for raw in refused {
            XCTAssertThrowsError(try APIAddress.parse(raw), "\(raw) must not be accepted") { error in
                guard case ShellError.invalidAddress = error else {
                    return XCTFail("\(raw) failed with \(error) instead of an address error")
                }
            }
        }
    }

    func testAnAddressWithoutAUsablePortIsRefused() {
        for raw in ["127.0.0.1", "127.0.0.1:", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:http", "", "   "] {
            XCTAssertThrowsError(try APIAddress.parse(raw), "\(raw) must not be accepted")
        }
    }

    func testAnUnbracketedIPv6AddressIsRefusedRatherThanGuessed() {
        XCTAssertThrowsError(try APIAddress.parse("::1:7946"))
        XCTAssertThrowsError(try APIAddress.parse("[::1:7946"))
        XCTAssertThrowsError(try APIAddress.parse("[::1]7946"))
    }
}
