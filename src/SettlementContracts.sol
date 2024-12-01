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

    // appid -> version -> batch root
    mapping(uint64 => mapping(uint64 => bytes32)) batchRoots;
    // appid -> current version
    mapping(uint64 => uint64) versions;
    // appid -> App details
    mapping(uint64 => AppId) appId;

    event StateUpdated(
        uint64 indexed _appId,
        uint64 indexed version, // what if we change it from use versions to only block.timestamp
        bytes32 batchRoot,
        address confirmer,
        uint64 timestamp,
        bytes32 batchHeaderHash,
        uint32 blobIndex
    );
    event ClaimAppID(uint64 indexed _appId, address owner, bytes32 provingSystemId);
    event TransferAppIdOwner(uint64 indexed _appId, address from, address to);
    event TransferOwner(address indexed from, address to);
    event DeleteAppId(uint64 indexed _appId);

    constructor(
        address _eigenDAServiceManager, address payable _alignedServiceAddr
    ) {
        eigenDAServiceManager = IEigenDAServiceManager(_eigenDAServiceManager);
        aligned = AlignedLayerServiceManager(_alignedServiceAddr);
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(owner == msg.sender, "NOT_OWNER");
        _;
    }

    function updateState(
        uint64 _appId,
        bytes32 _batchHeaderHash,
        EigenDACert calldata cert,
        VerificationData calldata verificationData
    ) public {
        require(_appId > 0, "Invalid Application ID");
        require(appId[_appId].claimed, "NOT_CLAIMED");
        require(appId[_appId].owner == msg.sender, "NOT_AUTH");
        if (
            verificationData.provingSystemAuxDataCommitment != appId[_appId].provingSystemId
        ) {
            revert ProvingSystemIdIsNotValid(verificationData.provingSystemAuxDataCommitment);
        }
        // TODO: check aligned data == cert header - by X,Y commitment

        bool isNewStateVerified = aligned.verifyBatchInclusion(
            verificationData.proofCommitment,
            verificationData.pubInputCommitment,
            verificationData.provingSystemAuxDataCommitment,
            verificationData.proofGeneratorAddr,
            verificationData.batchMerkleRoot,
            verificationData.merkleProof,
            verificationData.verificationDataBatchIndex,
            verificationData.batcherPaymentService
        );

        if(isNewStateVerified) {
            EigenDARollupUtils.verifyBlob(
                cert.blobHeader, eigenDAServiceManager, cert.blobVerificationProof
            );

            // Increment the version number for the application
            versions[_appId] += 1;
            uint64 newVersion = versions[_appId];

            batchRoots[_appId][newVersion] = verificationData.batchMerkleRoot;

            emit StateUpdated(
                _appId,
                newVersion,
                verificationData.batchMerkleRoot,
                msg.sender,
                uint64(block.timestamp),
                _batchHeaderHash,
                cert.blobVerificationProof.blobIndex
            );
        } else {
            revert NewStateIsNotValid();
        }
    }

    function claimAppId(uint64 _appId, bytes32 _provingSystemId) public {
        require(!appId[_appId].claimed, "ALREADY_CLAIMED");
        require(_provingSystemId != bytes32(0), "WRONG_SYSTEM");

        appId[_appId] = AppId({
            owner: msg.sender,
            provingSystemId: _provingSystemId,
            claimed: true
        });

        emit ClaimAppID(_appId, msg.sender, _provingSystemId);
    }

    function deleteAppId(uint64 _appId) public {
        require(appId[_appId].claimed, "NOT_CLAIMED");
        require(appId[_appId].owner == msg.sender, "NOT_OWNER");

        uint64 versionsCount = versions[_appId];

        for (uint64 i = 1; i <= versionsCount; i++) {
            delete batchRoots[_appId][i];
        }
        delete versions[_appId];
        delete appId[_appId];

        emit DeleteAppId(_appId);
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

    /**
     * @notice Retrieves the state commitment for a given application and version.
     * @param _appId Identifier for the application.
     * @param _version Specific version of the state to retrieve.
     * @return stateRoot The bytes32.
     */
    function getStateByVersion(uint64 _appId, uint64 _version) public view returns (bytes32 stateRoot) {
        require(_version > 0 && _version <= versions[_appId], "Version does not exist");
        return batchRoots[_appId][_version];
    }

    function getVersionsCount(uint64 _appId) public view returns (uint64) {
        return versions[_appId];
    }

    function getApp(uint64 _appId) public view returns (AppId memory) {
        return appId[_appId];
    }

    function getEigenDAServiceManagerAddress() public view returns (address) {
        return address(eigenDAServiceManager);
    }

    function getAlignedServiceManagerAddress() public view returns (address) {
        return address(aligned);
    }

    function transferAppIdOwner(uint64 _appId, address _newOwner) public {
        require(appId[_appId].owner == msg.sender, "NOT_AUTH");
        appId[_appId].owner = _newOwner;
        emit TransferAppIdOwner(_appId, msg.sender, _newOwner);
    }

    function transferOwner(address _newOwner) public onlyOwner() {
        owner = _newOwner;
        emit TransferOwner(msg.sender, _newOwner);
    }
}
