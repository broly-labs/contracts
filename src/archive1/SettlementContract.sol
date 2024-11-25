// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import {EigenDARollupUtils} from "@eigenda/eigenda-utils/libraries/EigenDARollupUtils.sol";
import {IEigenDAServiceManager} from "@eigenda/eigenda-utils/interfaces/IEigenDAServiceManager.sol";
import "./IDataAvailabilityProtocol.sol";

/// @title Settlement Contract for Verified State Storage with EigenDA
contract SettlementContract {
    IEigenDAServiceManager eigenDAServiceManager;
    IDataAvailabilityProtocol dataAvailabilityProtocol;
    address private owner;

    struct StateCommitment {
        bytes32 batchRoot;                   // ID for data availability reference in EigenDA
        uint256 blobIndex;
        uint256 timestamp;
        uint256 applicationId;                // Identifier for the specific application
        uint256 version;                     // Version to track history and revisions
        address confirmer;
    }

    struct AppId {
        address owner;
        bool claimed;
    }

    // appid -> all versions
    mapping(uint256 => uint256[]) public applicationStateHistory; // Map applicationId to list of versions
    // appid -> version -> da
    mapping(uint256 => mapping(uint256 => StateCommitment)) public stateCommitments; // Map version to StateCommitment
    // appid -> current indexe
    mapping(uint256 => uint256) public currentCommitmentIndexes;
    // appid -> owner
    mapping(uint256 => AppId) public appIdOwner;

    event StateUpdated(
        uint256 indexed applicationId,
        bytes32 indexed batchRoot,
        uint256 indexed blobIndex,
        uint256 version,
        uint256 timestamp,
        address confirmer
    );

    constructor(address _eigenDAServiceManager, address _dataAvailabilityProtocol) {
        eigenDAServiceManager = IEigenDAServiceManager(_eigenDAServiceManager);
        dataAvailabilityProtocol = IDataAvailabilityProtocol(_dataAvailabilityProtocol);
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(owner == msg.sender, "NOT_OWNER");
        _;
    }

    /**
     * @notice Receives the verified DA Certificate to store the latest application state.
     * @param applicationId Unique identifier for the application.
     * @param batchMerkleRoot Merkle root of the batch in EigenDA.
     * @param blobIndex The Blob index.
     * @param dataAvailability The EigenDA blob verification proof.
     */
    function updateState(
        uint256 applicationId,
        bytes32 batchMerkleRoot,
        uint256 blobIndex,
        bytes calldata dataAvailability,
        address confirmer
    ) public {
        require(applicationId > 0, "Invalid applicationId");
        require(appIdOwner[applicationId].owner == msg.sender, "NOT_AUTH");

        dataAvailabilityProtocol.verifyMessage(
            dataAvailability
        );

        currentCommitmentIndexes[applicationId]++;

        // Version control for historical access
        uint256 newVersion = applicationStateHistory[applicationId].length + 1;

        // Store the verified state
        stateCommitments[applicationId][currentCommitmentIndexes[applicationId]] = StateCommitment({
            batchRoot: batchMerkleRoot,
            blobIndex: blobIndex,
            timestamp: block.timestamp,
            applicationId: applicationId,
            version: newVersion,
            confirmer: confirmer
        });

        // Update history mapping
        applicationStateHistory[applicationId].push(currentCommitmentIndexes[applicationId]);

        emit StateUpdated(
            applicationId, batchMerkleRoot, blobIndex, newVersion, block.timestamp, confirmer
        );
    }

    function claimAppID(uint256 _appId) public {
        require(_appId > 0, "Invalid applicationId");
        require(appIdOwner[_appId].claimed == false, "ALREADY_CLAIMED");
    
        appIdOwner[_appId].owner = msg.sender;
        appIdOwner[_appId].claimed = true;
    }

    /**
     * @notice Retrieves the latest state root for a given application.
     * @param applicationId Identifier for the application.
     * @return stateRoot The latest state root, or `bytes32(0)` if no state is found.
     */
    function getLatestBatchRoot(uint256 applicationId) public view returns (bytes32 stateRoot) {
        uint256[] memory history = applicationStateHistory[applicationId];
        if (history.length == 0) return bytes32(0); // No states for this application

        uint256 latestIndex = history[history.length - 1];
        return stateCommitments[applicationId][latestIndex].batchRoot;
    }

    /**
     * @notice Retrieves the state commitment for a given application and version.
     * @param applicationId Identifier for the application.
     * @param version Specific version of the state to retrieve.
     * @return stateCommitment The StateCommitment struct for the specified version.
     */
    function getStateByVersion(uint256 applicationId, uint256 version) public view returns (StateCommitment memory stateCommitment) {
        uint256[] memory history = applicationStateHistory[applicationId];
        require(version > 0 && version <= history.length, "Version does not exist");

        uint256 index = history[version - 1];
        return stateCommitments[applicationId][index];
    }

    function getAllVersions(uint256 appId) public view returns (uint256[] memory versionArray) {
        return applicationStateHistory[appId];
    }

    function getVersionsCount(uint256 _applicationId) public view returns (uint256) {
        return applicationStateHistory[_applicationId].length;
    }

    function getDAProtocolAddress() public view returns (address) {
        return address(dataAvailabilityProtocol);
    }

    function getEigenDAServiceManagerAddress() public view returns (address) {
        return address(eigenDAServiceManager);
    }

    function getAppIdOwner(uint256 _applicationId) public view returns (address) {
        return appIdOwner[_applicationId].owner;
    }

    function transferAppIdOwner(uint256 _applicationId, address _newOwner) public {
        require(appIdOwner[_applicationId].owner == msg.sender, "NOT_AUTH");
        appIdOwner[_applicationId].owner = _newOwner;
    }
    
    function changeDAProtocolAddress(address _dataAvailabilityProtocol) public onlyOwner() {
        dataAvailabilityProtocol = IDataAvailabilityProtocol(_dataAvailabilityProtocol);
    }

    function transferOwner(address _newOwner) public onlyOwner() {
        owner = _newOwner;
    }
}
