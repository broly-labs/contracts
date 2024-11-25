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

    // appid -> current version
    mapping(uint64 => uint64) versions;
    // appid -> App details
    mapping(uint64 => AppId) appId;

    event StateUpdated(
        uint64 indexed applicationId,
        uint64 indexed version, // what if we change it from use versions to only block.timestamp
        address confirmer,
        uint64 timestamp,
        bytes32 batchHeaderHash,
        uint32 blobIndex
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
        // TODO: verify - proofGeneratorAddr == appId owner
        require(address(verificationData.proofGeneratorAddr) == msg.sender, "NOT_AUTH");
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

            emit StateUpdated(
                _appId, versions[_appId], msg.sender, uint64(block.timestamp),
                _batchHeaderHash, cert.blobVerificationProof.blobIndex
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

        delete versions[_appId];
        delete appId[_appId];

        emit DeleteAppId(_appId);
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
