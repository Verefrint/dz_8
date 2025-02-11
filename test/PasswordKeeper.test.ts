import { ethers, expect, loadFixture } from "./setup";

describe("PasswordKeeper", async function() {

    async function deploy() {
        const [owner, user2] = await ethers.getSigners();

        const factory = await ethers.getContractFactory("PasswordKeeper", owner)
        const contract = await factory.deploy("abc")
        await contract.waitForDeployment();

        return { owner, user2, contract }
    }

    it("should change password", async function() {
        const { owner, user2, contract } = await loadFixture(deploy)

        expect(await contract.connect(owner).getPassword()).to.eq("abc")

        const nonce = 1;
        
        const nowInSeconds = Math.floor(Date.now() / 1000);
        const oneDayInSeconds = 86400;
        const tomorrowInSeconds = nowInSeconds + oneDayInSeconds;

        let hash = ethers.solidityPackedKeccak256(
            ["address", "address", "uint256", "uint256"],
            [user2.address, owner.address, nonce, tomorrowInSeconds]
        )

        let messageHashBin = ethers.toBeArray(hash)
        const signature = await owner.signMessage(messageHashBin)
        
        await contract.connect(user2).changePassword("ab", nonce, signature, tomorrowInSeconds)

        await expect(contract.connect(user2).changePassword("ab", nonce, signature, tomorrowInSeconds)).to.be.revertedWithCustomError(contract, "NonceNotAvailable");

        hash = ethers.solidityPackedKeccak256(
            ["address", "address", "uint256", "uint256"],
            [user2.address, owner.address, nonce, tomorrowInSeconds]
        )

        messageHashBin = ethers.toBeArray(hash)
        const invalidSignature = await user2.signMessage(messageHashBin)

        await expect(contract.connect(user2).changePassword("ab", nonce + 1, invalidSignature, tomorrowInSeconds)).to.be.revertedWithCustomError(contract, "InvalidSignature");

        expect(await contract.getPassword()).to.be.eq("ab")

        const expiredTime = nowInSeconds - oneDayInSeconds;

        await expect(contract.connect(user2).changePassword("ab", nonce + 1, signature, expiredTime)).to.be.revertedWithCustomError(contract, "MessageExpired");
    })
})