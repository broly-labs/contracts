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

    // appid -> version -> new state root
    mapping(uint64 => mapping(uint64 => bytes32)) stateCommitments;
    // appid -> current version
    mapping(uint64 => uint64) versions;
    // appid -> App details
    mapping(uint64 => AppId) appId;

    event StateUpdated(
        uint64 indexed applicationId,
        bytes32 indexed newState,
        uint64 version,
        address confirmer,
        bytes requestBlobId
    );
    event ClaimAppID(uint64 indexed applicationId, address owner, bytes32 provingSystemId);
    event TransferAppIdOwner(uint64 indexed applicationId, address from, address to);
    event TransferOwner(address indexed from, address to);
    event DeleteAppId(uint64 indexed applicationId);

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

    function packHeader(uint64 _appId, uint64 _newVersion) internal pure returns (bytes memory) {
        bytes memory header = abi.encodePacked(_appId, _newVersion);

        return header;
    }

    // TODO: make it internal
    function formEigenDADataHash(
        uint64 _appId, uint64 _newVersion, EigenDACert calldata cert
    ) public pure returns (bytes32) {
        bytes memory header = packHeader(_appId, _newVersion);

        return (
            keccak256(bytes.concat(header, abi.encode(cert)))
        );
    }

    function updateState(
        uint64 _appId,
        bytes calldata _requestBlobId,
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
        // TODO: verify - proofGeneratorAddr == appId owner
        // TODO: maybe check from aligned data == cert header - by XY commitment

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

            bytes32 newState = formEigenDADataHash(
                _appId, newVersion, cert
            );
            stateCommitments[_appId][newVersion] = newState;

            emit StateUpdated(_appId, newState, newVersion, msg.sender, _requestBlobId);
        } else {
            revert NewStateIsNotValid();
        }
    }

    function verifiyState(
        uint64 _appId, uint64 _version, EigenDACert calldata cert
    ) public view returns (bool) {
        bytes32 newStateRoot = formEigenDADataHash(
            _appId, _version, cert
        );

        return stateCommitments[_appId][_version] == newStateRoot;
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
            delete stateCommitments[_appId][i];
        }
        delete versions[_appId];
        delete appId[_appId];

        emit DeleteAppId(_appId);
    }

    /**
     * @notice Retrieves the latest state root for a given application.
     * @param applicationId Identifier for the application.
     * @return stateRoot The latest state root, or `bytes32(0)` if no state is found.
     */
    function getLatestStateRoot(uint64 applicationId) public view returns (bytes32 stateRoot) {
        uint64 latestVersion = versions[applicationId];
        if (latestVersion == 0) return bytes32(0); // No states for this application

        return stateCommitments[applicationId][latestVersion];
    }

    /**
     * @notice Retrieves the state commitment for a given application and version.
     * @param applicationId Identifier for the application.
     * @param version Specific version of the state to retrieve.
     * @return stateRoot The bytes32.
     */
    function getStateByVersion(uint64 applicationId, uint64 version) public view returns (bytes32 stateRoot) {
        require(version > 0 && version <= versions[applicationId], "Version does not exist");
        return stateCommitments[applicationId][version];
    }

    function getVersionsCount(uint64 _applicationId) public view returns (uint64) {
        return versions[_applicationId];
    }

    function getApp(uint64 _applicationId) public view returns (AppId memory) {
        return appId[_applicationId];
    }

    function getEigenDAServiceManagerAddress() public view returns (address) {
        return address(eigenDAServiceManager);
    }

    function getAlignedServiceManagerAddress() public view returns (address) {
        return address(aligned);
    }

    function transferAppIdOwner(uint64 _applicationId, address _newOwner) public {
        require(appId[_applicationId].owner == msg.sender, "NOT_AUTH");
        appId[_applicationId].owner = _newOwner;
        emit TransferAppIdOwner(_applicationId, msg.sender, _newOwner);
    }

    function transferOwner(address _newOwner) public onlyOwner() {
        owner = _newOwner;
        emit TransferOwner(msg.sender, _newOwner);
    }
}
