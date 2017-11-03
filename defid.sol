pragma solidity ^0.4.0;

//Def.ai distributed id and attestation contracts

contract DefID{

	address private owner;
	address private override;

	uint constant ERROR_EVENT = 1;
    uint constant WARNING_EVENT = 2;
    uint constant SIG_CHANGE_EVENT = 3;
    uint constant INFO_EVENT = 4;
    uint constant DEBUG_EVENT = 5;

    string public encryptionPublicKey;
    string public signingPublicKey;

	struct Attribute{
		bytes32 hash;
        mapping(bytes32 => Endorsement) endorsements;
        uint endorsementIncentive;
	}

	struct Endorsement {
        address endorser;
        bytes32 hash;
        bool accepted;
    }

	mapping (bytes32 => Attribute) public attrbutes;

	// modifier onlyowner {
 //        require(isOwner(msg.sender));
 //        _;
 //    }

    /**
     * Modifier to place a constraint on the user calling a function
     */
    modifier onlyBy(address _account) {
        if (msg.sender != _account) {
            revert();
        }
        _;
    }

	//contructor fn
	function DefID(){
		owner = msg.sender;
		override = owner;
	}

	event ChangeNotification(address indexed sender, uint status, bytes32 notificationMsg);

	function sendEvent(uint _status, bytes32 _notificationMsg) internal returns(bool){
		ChangeNotification(owner, _status, _notificationMsg);
		return true;
	}

	function getOwner() onlyBy(override) returns(address) {
        return owner;
    }

	function addAttribute(bytes32 _hash, uint _endorsementIncentive) onlyBy(owner) returns(bool){
		var attribute = attributes[_hash];
        if (attribute.hash == _hash) {
            sendEvent(SIG_CHANGE_EVENT, "A hash exists for the attribute");
            revert();
        }
        attribute.hash = _hash;
        attribute.endorsementIncentive = _endorsementIncentive;
        sendEvent(INFO_EVENT, "Attribute has been added and Endorsement Bounty set!");
        return true;
	}

	function removeAttribute(bytes32 _hash) onlyBy(owner) returns(bool){
		var attribute = attributes[_hash];
		if (attribute.hash != _hash){
			sendEvent(WARNING_EVENT, "Hash not found for attribute");
			revert();
		}
		delete attributes[_hash];
		sendEvent(SIG_CHANGE_EVENT, "Attribute has been removed");
		return true;
	}

	function updateAttribute(bytes32 _oldHash, bytes32 _newHash) onlyBy(owner) returns(bool){
		sendEvent(DEBUG_EVENT, "Attempting to update attribute");
        removeAttribute(_oldHash);
        addAttribute(_newHash);
        sendEvent(SIG_CHANGE_EVENT, "Attribute has been updated");
        return true;
	}

	/**
     * Adds an endorsement to an attribute; must provide a valid attributeHash.
     * See the docs for off-chain transfer of the encrypted endorsement information.
     */
    function addEndorsement(bytes32 _attributeHash, bytes32 _endorsementHash) returns(bool) {
        var attribute = attributes[_attributeHash];
        if (attribute.hash != _attributeHash) {
            sendEvent(ERROR_EVENT, "Attribute doesn't exist");
            revert();
        }
        var endorsement = attribute.endorsements[_endorsementHash];
        if (endorsement.hash == _endorsementHash) {
            sendEvent(ERROR_EVENT, "Endorsement already exists");
            revert();
        }
        endorsement.hash = _endorsementHash;
        endorsement.endorser = msg.sender;
        endorsement.accepted = false;
        sendEvent(INFO_EVENT, "Endorsement has been added");
        return true;
    }

    /**
     * Owner can mark an endorsement as accepted.
     */
    function acceptEndorsement(bytes32 _attributeHash, bytes32 _endorsementHash) onlyBy(owner) returns(bool) {
        var attribute = attributes[_attributeHash];
        var endorsement = attribute.endorsements[_endorsementHash];
        endorsement.accepted = true;
        transferEndorsementBounty(endorsement.endorser, attribute.endorsementIncentive);
        sendEvent(SIG_CHANGE_EVENT, "Endorsement has been acceptedby User and Bounty released!");
        return true;
    }

    /**
     * Checks that an endorsement _endorsementHash exists for the attribute _attributeHash.
     */
    function checkEndorsementExists(bytes32 _attributeHash, bytes32 _endorsementHash) returns(bool) {
        var attribute = attributes[_attributeHash];
        if (attribute.hash != _attributeHash) {
            sendEvent(ERROR_EVENT, "Attribute doesn't exist");
            return false;
        }
        var endorsement = attribute.endorsements[_endorsementHash];
        if (endorsement.hash != _endorsementHash) {
            sendEvent(ERROR_EVENT, "Endorsement doesn't exist");
            return false;
        }
        if (endorsement.accepted == true) {
            sendEvent(INFO_EVENT, "Endorsement exists for attribute");
            return true;
        } else {
            sendEvent(ERROR_EVENT, "Endorsement hasn't been accepted");
            return false;
        }
    }

    /**
     * Allows only the person who gave the endorsement the ability to remove it.
     */
    function removeEndorsement(bytes32 _attributeHash, bytes32 _endorsementHash) returns(bool) {
        var attribute = attributes[_attributeHash];
        var endorsement = attribute.endorsements[_endorsementHash];
        if (msg.sender == endorsement.endorser) {
            delete attribute.endorsements[_endorsementHash];
            sendEvent(SIG_CHANGE_EVENT, "Endorsement removed");
            return true;
        }
        if (msg.sender == owner && endorsement.accepted == false) {
            delete attribute.endorsements[_endorsementHash];
            sendEvent(SIG_CHANGE_EVENT, "Endorsement denied");
            return true;
        }
        sendEvent(SIG_CHANGE_EVENT, "Endorsement removal failed");
        revert();
    }

    function transferEndorsementBounty(address endorser, uint amount) private{
    	assert(endorser.send(amount));
    }

    /**
     * Allows only the account owner to create or update encryptionPublicKey.
     * Only 1 encryptionPublicKey is allowed per account, therefore use same set
     * method for both create and update.
     */
    function setEncryptionPublicKey(string _myEncryptionPublicKey) onlyBy(owner) checkBlockLock() returns(bool) {
        encryptionPublicKey = _myEncryptionPublicKey;
        sendEvent(SIG_CHANGE_EVENT, "Encryption key added");
        return true;
    }

    /**
     * Allows only the account owner to create or update signingPublicKey.
     * Only 1 signingPublicKey allowed per account, therefore use same set method
     * for both create and update.
     */
    function setSigningPublicKey(string _mySigningPublicKey) onlyBy(owner) checkBlockLock() returns(bool) {
        signingPublicKey = _mySigningPublicKey;
        sendEvent(SIG_CHANGE_EVENT, "Signing key added");
        return true;
    }

    /**
     * Kills the contract and prevents further actions on it.
     */
    function kill() onlyBy(owner) returns(uint) {
        suicide(owner);
        sendEvent(WARNING_EVENT, "Contract killed");
    }


}