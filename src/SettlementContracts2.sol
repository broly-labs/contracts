// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import {EigenDARollupUtils} from "@eigenda/eigenda-utils/libraries/EigenDARollupUtils.sol";
import {IEigenDAServiceManager} from "@eigenda/eigenda-utils/interfaces/IEigenDAServiceManager.sol";
import "aligned_layer/contracts/src/core/AlignedLayerServiceManager.sol";

error ProvingSystemIdIsNotValid(bytes32);
error NewStateIsNotValid();

contract SettlementContract {
    IEigenDAServiceManager eigenDAServiceManager;
    AlignedLayerServiceManager aligned;
    address owner;

    struct AppId {
        address owner;
        bytes32 provingSystemId;
        bool claimed;
        bool isGlobal;
    }

    struct GlobalStateUpdate {
        uint256 sequenceNumber;
        uint64 appId;
        bytes32 batchRoot;
        uint64 version;
        uint64 timestamp;
    }

    struct EigenDACert {
        EigenDARollupUtils.BlobVerificationProof blobVerificationProof;
        IEigenDAServiceManager.BlobHeader blobHeader;
    }

    struct VerificationData {
        bytes32 proofCommitment;
        bytes32 pubInputCommitment;
        bytes32 provingSystemAuxDataCommitment;
        bytes20 proofGeneratorAddr;
        bytes32 batchMerkleRoot;
        bytes merkleProof;
        uint256 verificationDataBatchIndex;
        address batcherPaymentService;
    }

    uint256 globalSequenceCounter;
    mapping(uint64 => AppId) appId;
    mapping(uint64 => uint64) versions; // Per-app versions
    mapping(uint256 => GlobalStateUpdate) globalUpdates; // Global sequencing
    mapping(uint64 => mapping(uint64 => bytes32)) batchRoots; // appId -> version -> acc batchRoot

    event StateUpdated(
        uint256 indexed sequenceNumber,
        uint64 indexed appId,
        uint64 version,
        bytes32 batchRoot,
        uint64 timestamp,
        bytes32 batchHeaderHash,
        uint32 blobIndex
    );
    event ClaimAppID(uint64 indexed appId, address owner, bytes32 provingSystemId);
    event TransferAppIdOwner(uint64 indexed appId, address from, address to);
    event TransferOwner(address indexed from, address to);
    event DeleteAppId(uint64 indexed appId);

    modifier onlyOwner() {
        require(msg.sender == owner, "NOT_OWNER");
        _;
    }

    constructor(address _eigenDAServiceManager, address payable _alignedServiceAddr) {
        eigenDAServiceManager = IEigenDAServiceManager(_eigenDAServiceManager);
        aligned = AlignedLayerServiceManager(_alignedServiceAddr);
        owner = msg.sender;
    }

    function claimAppId(uint64 _appId, bytes32 _provingSystemId, bool _isGlobal) public {
        require(!appId[_appId].claimed, "ALREADY_CLAIMED");
        require(_provingSystemId != bytes32(0), "INVALID_PROVING_SYSTEM");

        appId[_appId] = AppId({
            owner: msg.sender,
            provingSystemId: _provingSystemId,
            claimed: true,
            isGlobal: _isGlobal
        });

        emit ClaimAppID(_appId, msg.sender, _provingSystemId);
    }

    function updateState(
        uint64 _appId,
        bytes32 _batchHeaderHash,
        EigenDACert calldata cert,
        VerificationData calldata verificationData
    ) public {
        require(appId[_appId].claimed, "NOT_CLAIMED");
        require(appId[_appId].owner == msg.sender, "NOT_AUTHORIZED");

        if (verificationData.provingSystemAuxDataCommitment != appId[_appId].provingSystemId) {
            revert ProvingSystemIdIsNotValid(verificationData.provingSystemAuxDataCommitment);
        }

        bool isValidState = aligned.verifyBatchInclusion(
            verificationData.proofCommitment,
            verificationData.pubInputCommitment,
            verificationData.provingSystemAuxDataCommitment,
            verificationData.proofGeneratorAddr,
            verificationData.batchMerkleRoot,
            verificationData.merkleProof,
            verificationData.verificationDataBatchIndex,
            verificationData.batcherPaymentService
        );

        if (!isValidState) {
            revert NewStateIsNotValid();
        }

        EigenDARollupUtils.verifyBlob(
            cert.blobHeader,
            eigenDAServiceManager,
            cert.blobVerificationProof
        );

        versions[_appId] += 1;
        uint64 currentVersion = versions[_appId];
        bytes32 newAccBatchRoot = getAccBatchRoot(
            _appId, currentVersion, verificationData.batchMerkleRoot
        );
        batchRoots[_appId][currentVersion] = newAccBatchRoot;

        if (appId[_appId].isGlobal) {
            globalSequenceCounter++;
            uint256 sequenceNumber = globalSequenceCounter;

            globalUpdates[sequenceNumber] = GlobalStateUpdate({
                sequenceNumber: sequenceNumber,
                appId: _appId,
                batchRoot: newAccBatchRoot,
                version: currentVersion,
                timestamp: uint64(block.timestamp)
            });

            emit StateUpdated(
                sequenceNumber,
                _appId,
                currentVersion,
                newAccBatchRoot,
                uint64(block.timestamp),
                _batchHeaderHash,
                cert.blobVerificationProof.blobIndex
            );
        } else {
            emit StateUpdated(
                0,
                _appId,
                currentVersion,
                newAccBatchRoot,
                uint64(block.timestamp),
                _batchHeaderHash,
                cert.blobVerificationProof.blobIndex
            );
        }
    }

    function deleteAppId(uint64 _appId) public {
        require(appId[_appId].claimed, "NOT_CLAIMED");
        require(appId[_appId].owner == msg.sender, "NOT_AUTHORIZED");

        uint64 appVersionCount = versions[_appId];
        for (uint64 i = 1; i <= appVersionCount; i++) {
            delete batchRoots[_appId][i];
        }

        delete versions[_appId];
        delete appId[_appId];

        emit DeleteAppId(_appId);
    }

    function getAccBatchRoot(
        uint64 _appId, uint64 currentVersion, bytes32 newBatchRoot
    ) internal view returns (bytes32) {
        bytes32 prevBatchRoot = batchRoots[_appId][currentVersion - 1];

        return keccak256(
            abi.encodePacked(prevBatchRoot, newBatchRoot)
        );
    }

    /**
     * @notice Retrieves the latest state root for a given application.
     * @param _appId Identifier for the application.
     * @return stateRoot The latest state root, or `bytes32(0)` if no state is found.
     */
    function getLatestStateRoot(uint64 _appId) public view returns (bytes32 stateRoot) {
        uint64 latestVersion = versions[_appId];
        if (latestVersion == 0) return bytes32(0); // No states for this application

        return batchRoots[_appId][latestVersion];
    }

    function transferAppIdOwner(uint64 _appId, address _newOwner) public {
        require(appId[_appId].claimed, "NOT_CLAIMED");
        require(appId[_appId].owner == msg.sender, "NOT_AUTHORIZED");

        appId[_appId].owner = _newOwner;

        emit TransferAppIdOwner(_appId, msg.sender, _newOwner);
    }

    function transferOwner(address _newOwner) public onlyOwner {
        require(_newOwner != address(0), "INVALID_ADDRESS");
        emit TransferOwner(owner, _newOwner);
        owner = _newOwner;
    }

    function getGlobalState(uint256 sequenceNumber) public view returns (GlobalStateUpdate memory) {
        return globalUpdates[sequenceNumber];
    }

    function getLatestAppVersion(uint64 _appId) public view returns (uint64) {
        return versions[_appId];
    }

    function getAppDetails(uint64 _appId) public view returns (AppId memory) {
        return appId[_appId];
    }

    function getVersionsCount(uint64 _appId) public view returns (uint64) {
        return versions[_appId];
    }

    function getSequenceCount() public view returns (uint256) {
        return globalSequenceCounter;
    }

    function getBatchRoot(uint64 _appId, uint64 version) public view returns (bytes32) {
        return batchRoots[_appId][version];
    }

    function getEigenDAServiceManagerAddress() public view returns (address) {
        return address(eigenDAServiceManager);
    }

    function getAlignedServiceManagerAddress() public view returns (address) {
        return address(aligned);
    }
}
