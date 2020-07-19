/************************************************************************
 * Name: Dump Keychain
 * OS: iOS
 * Author: @chaitin
 * Source: https://github.com/chaitin/passionfruit
*************************************************************************/

function constantLookup(v) {
    if(v in kSecConstantReverse) {
    return kSecConstantReverse[v];
    } else {
    return v;
    }
}

function odas(raw) {
    try {
    const data = new ObjC.Object(raw)
    return Memory.readUtf8String(data.bytes(), data.length())
    } catch (_) {
    try {
        return raw.toString()
    } catch (__) {
        return ''
    }
    }
}

function decodeOd(item, flags) {
    const constraints = item
    const constraintEnumerator = constraints.keyEnumerator()

    var constraintKey;

    for (constraintKey = 0; constraintKey !== null; constraintEnumerator.nextObject()) {
    switch (odas(constraintKey)) {
        case 'cpo':
        flags.push('kSecAccessControlUserPresence')
        break

        case 'cup':
        flags.push('kSecAccessControlDevicePasscode')
        break

        case 'pkofn':
        flags.push(constraints.objectForKey_('pkofn') === 1 ? 'Or' : 'And')
        break

        case 'cbio':
        flags.push(constraints.objectForKey_('cbio').count() === 1
            ? 'kSecAccessControlTouchIDAny'
            : 'kSecAccessControlTouchIDCurrentSet')
        break

        default:
        break
    }
    }
}

function decodeAcl(entry,SecAccessControlGetConstraints) {
    // No access control? Move along.
    if (!entry.containsKey_(kSecAttrAccessControl))
    return []

    const constraints = SecAccessControlGetConstraints(entry.objectForKey_(kSecAttrAccessControl))
    if (constraints.isNull())
    return []

    const accessControls = ObjC.Object(constraints)
    const flags = []
    const enumerator = accessControls.keyEnumerator()

    var key;

    for (key = enumerator.nextObject(); key !== null; key = enumerator.nextObject()) {
    const item = accessControls.objectForKey_(key)
    switch (odas(key)) {
        case 'dacl':
        break
        case 'osgn':
        flags.push('PrivateKeyUsage')
        case 'od':
        decodeOd(item, flags)
        break
        case 'prp':
        flags.push('ApplicationPassword')
        break

        default:
        break
    }
    }
    return flags
}

const kSecReturnAttributes = 'r_Attributes',
    kSecReturnData = 'r_Data',
    kSecReturnRef = 'r_Ref',
    kSecMatchLimit = 'm_Limit',
    kSecMatchLimitAll = 'm_LimitAll',
    kSecClass = 'class',
    kSecClassKey = 'keys',
    kSecClassIdentity = 'idnt',
    kSecClassCertificate = 'cert',
    kSecClassGenericPassword = 'genp',
    kSecClassInternetPassword = 'inet',
    kSecAttrService = 'svce',
    kSecAttrAccount = 'acct',
    kSecAttrAccessGroup = 'agrp',
    kSecAttrLabel = 'labl',
    kSecAttrCreationDate = 'cdat',
    kSecAttrAccessControl = 'accc',
    kSecAttrGeneric = 'gena',
    kSecAttrSynchronizable = 'sync',
    kSecAttrModificationDate = 'mdat',
    kSecAttrServer = 'srvr',
    kSecAttrDescription = 'desc',
    kSecAttrComment = 'icmt',
    kSecAttrCreator = 'crtr',
    kSecAttrType = 'type',
    kSecAttrScriptCode = 'scrp',
    kSecAttrAlias = 'alis',
    kSecAttrIsInvisible = 'invi',
    kSecAttrIsNegative = 'nega',
    kSecAttrHasCustomIcon = 'cusi',
    kSecProtectedDataItemAttr = 'prot',
    kSecAttrAccessible = 'pdmn',
    kSecAttrAccessibleWhenUnlocked = 'ak',
    kSecAttrAccessibleAfterFirstUnlock = 'ck',
    kSecAttrAccessibleAlways = 'dk',
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly = 'aku',
    kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly = 'cku',
    kSecAttrAccessibleAlwaysThisDeviceOnly = 'dku'

const kSecConstantReverse = {
    r_Attributes: 'kSecReturnAttributes',
    r_Data: 'kSecReturnData',
    r_Ref: 'kSecReturnRef',
    m_Limit: 'kSecMatchLimit',
    m_LimitAll: 'kSecMatchLimitAll',
    class: 'kSecClass',
    keys: 'kSecClassKey',
    idnt: 'kSecClassIdentity',
    cert: 'kSecClassCertificate',
    genp: 'kSecClassGenericPassword',
    inet: 'kSecClassInternetPassword',
    svce: 'kSecAttrService',
    acct: 'kSecAttrAccount',
    agrp: 'kSecAttrAccessGroup',
    labl: 'kSecAttrLabel',
    srvr: 'kSecAttrServer',
    cdat: 'kSecAttrCreationDate',
    accc: 'kSecAttrAccessControl',
    gena: 'kSecAttrGeneric',
    sync: 'kSecAttrSynchronizable',
    mdat: 'kSecAttrModificationDate',
    desc: 'kSecAttrDescription',
    icmt: 'kSecAttrComment',
    crtr: 'kSecAttrCreator',
    type: 'kSecAttrType',
    scrp: 'kSecAttrScriptCode',
    alis: 'kSecAttrAlias',
    invi: 'kSecAttrIsInvisible',
    nega: 'kSecAttrIsNegative',
    cusi: 'kSecAttrHasCustomIcon',
    prot: 'kSecProtectedDataItemAttr',
    pdmn: 'kSecAttrAccessible',
    ak: 'kSecAttrAccessibleWhenUnlocked',
    ck: 'kSecAttrAccessibleAfterFirstUnlock',
    dk: 'kSecAttrAccessibleAlways',
    aku: 'kSecAttrAccessibleWhenUnlockedThisDeviceOnly',
    cku: 'kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly',
    dku: 'kSecAttrAccessibleAlwaysThisDeviceOnly'
}

const kSecClasses = [  kSecClassKey,kSecClassIdentity,kSecClassCertificate, kSecClassGenericPassword,kSecClassInternetPassword ];



const NSMutableDictionary = ObjC.classes.NSMutableDictionary

const SecItemCopyMatching = new NativeFunction(ptr(Module.findExportByName('Security', 'SecItemCopyMatching')), 'pointer', ['pointer', 'pointer'])
const SecItemDelete = new NativeFunction(ptr(Module.findExportByName('Security', 'SecItemDelete')), 'pointer', ['pointer'])
const SecAccessControlGetConstraints = new NativeFunction(
ptr(Module.findExportByName('Security', 'SecAccessControlGetConstraints')),
'pointer', ['pointer']
)

const NSCFBoolean = ObjC.classes.__NSCFBoolean
const kCFBooleanTrue = NSCFBoolean.numberWithBool_(true)

const result = []

const query = NSMutableDictionary.alloc().init()
query.setObject_forKey_(kCFBooleanTrue, kSecReturnAttributes)
query.setObject_forKey_(kCFBooleanTrue, kSecReturnData)
query.setObject_forKey_(kCFBooleanTrue, kSecReturnRef)
query.setObject_forKey_(kSecMatchLimitAll, kSecMatchLimit)

kSecClasses.forEach(function(clazz) {
query.setObject_forKey_(clazz, kSecClass)

const p = Memory.alloc(Process.pointerSize)
const status = SecItemCopyMatching(query, p)
/* eslint eqeqeq: 0 */
if (status != 0x00)
    return

const arr = new ObjC.Object(Memory.readPointer(p))
var i,size;
for (i = 0, size = arr.count(); i < size; i++) {
    const item = arr.objectAtIndex_(i)
    result.push({
    clazz: constantLookup(clazz),
    creation: odas(item.objectForKey_(kSecAttrCreationDate)),
    modification: odas(item.objectForKey_(kSecAttrModificationDate)),
    description: odas(item.objectForKey_(kSecAttrDescription)),
    comment: odas(item.objectForKey_(kSecAttrComment)),
    creator: odas(item.objectForKey_(kSecAttrCreator)),
    type: odas(item.objectForKey_(kSecAttrType)),
    scriptCode: odas(item.objectForKey_(kSecAttrScriptCode)),
    alias: odas(item.objectForKey_(kSecAttrAlias)),
    invisible: odas(item.objectForKey_(kSecAttrIsInvisible)),
    negative: odas(item.objectForKey_(kSecAttrIsNegative)),
    customIcon: odas(item.objectForKey_(kSecAttrHasCustomIcon)),
    protected: odas(item.objectForKey_(kSecProtectedDataItemAttr)),
    accessControl: decodeAcl(item,SecAccessControlGetConstraints).join(' '),
    accessibleAttribute: constantLookup(odas(item.objectForKey_(kSecAttrAccessible))),
    entitlementGroup: odas(item.objectForKey_(kSecAttrAccessGroup)),
    generic: odas(item.objectForKey_(kSecAttrGeneric)),
    service: odas(item.objectForKey_(kSecAttrService)),
    account: odas(item.objectForKey_(kSecAttrAccount)),
    label: odas(item.objectForKey_(kSecAttrLabel)),
    data: odas(item.objectForKey_('v_Data'))
    })
}
});

send("**** KEYCHAIN DUMP ****");
var j,k,currentEntry;
for(k in result) {
send("\tEntry " + k);
currentEntry = result[k];
for(j in currentEntry) {
    if(currentEntry[j]) {
    send("\t\t" + j + ": " + currentEntry[j]);
    }
}    
}
send("**** END KEYCHAIN DUMP ****");

