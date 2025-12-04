// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title PrizePool - simple escrow used by web3quiz-zone
/// @notice Minimal contract. For production, add role management, timelocks, and emergency withdraws.
contract PrizePool {
    address public admin;

    event Funded(address indexed from, uint256 amount);
    event Payout(address indexed to, uint256 amount);
    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);

    modifier onlyAdmin() {
        require(msg.sender == admin, "PrizePool: only admin");
        _;
    }

    constructor(address _admin) {
        require(_admin != address(0), "invalid admin");
        admin = _admin;
    }

    receive() external payable {
        emit Funded(msg.sender, msg.value);
    }

    function fund() external payable {
        emit Funded(msg.sender, msg.value);
    }

    function payWinner(address payable to, uint256 amount) external onlyAdmin {
        require(address(this).balance >= amount, "insufficient funds");
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "transfer failed");
        emit Payout(to, amount);
    }

    function setAdmin(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "invalid admin");
        address old = admin;
        admin = newAdmin;
        emit AdminChanged(old, newAdmin);
    }

    function balance() external view returns (uint256) {
        return address(this).balance;
    }
}