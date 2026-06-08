// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract EventPlayground {
    event TransferLike(address indexed from, address indexed to, uint256 value);
    event StaticArgs(address user, bool ok, bytes4 sig, bytes32 tag, uint256 amount);
    event DynamicArgs(string note, bytes blob, uint256[] nums);
    event IndexedDynamic(string indexed note, bytes indexed blob);
    event DynamicSimple(string note, bytes blob);
    struct User {
        address addr;
        string name;
        uint256 balance;
    }
    event StructArgs(User user, bool isActive);
    event ArrayArgs(address[] accounts, bool[] flags);

    function emitTransferLike(address from, address to, uint256 value) external {
        emit TransferLike(from, to, value);
    }

    function emitDynamicSimple() external {
        emit DynamicSimple("hello", hex"beef");
    }

    function emitStructSample() external {
        User memory u = User(0x1111111111111111111111111111111111111111, "Alice", 100);
        emit StructArgs(u, true);
    }

    function emitArraySample() external {
        address[] memory accounts = new address[](2);
        accounts[0] = 0x1111111111111111111111111111111111111111;
        accounts[1] = 0x2222222222222222222222222222222222222222;
        bool[] memory flags = new bool[](2);
        flags[0] = true;
        flags[1] = false;
        emit ArrayArgs(accounts, flags);
    }

    function emitStaticSample() external {
        emit StaticArgs(
            0x1111111111111111111111111111111111111111,
            true,
            0xdeadbeef,
            bytes32("tag"),
            42
        );
    }

    function emitStaticCustom(address user, bool ok, bytes4 sig, bytes32 tag, uint256 amount) external {
        emit StaticArgs(user, ok, sig, tag, amount);
    }

    function emitDynamicSample() external {
        uint256[] memory nums = new uint256[](2);
        nums[0] = 1;
        nums[1] = 2;
        emit DynamicArgs("hello", hex"beef", nums);
    }

    function emitIndexedDynamicSample() external {
        emit IndexedDynamic("hello", hex"beef");
    }
}