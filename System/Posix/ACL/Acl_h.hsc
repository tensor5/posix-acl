module System.Posix.ACL.Acl_h where

import           Foreign
import           Foreign.C
import           System.Posix.Types (CSsize (..))

#include <sys/acl.h>

type AclTypeT = #{type acl_type_t}
type AclTagT = #{type acl_tag_t}
type AclPermT = #{type acl_perm_t}

aclRead :: AclPermT
aclRead = #{const ACL_READ}

aclWrite :: AclPermT
aclWrite = #{const ACL_WRITE}

aclExecute :: AclPermT
aclExecute = #{const ACL_EXECUTE}


aclUndefinedTag :: AclTagT
aclUndefinedTag = #{const ACL_UNDEFINED_TAG}

aclUserObj :: AclTagT
aclUserObj = #{const ACL_USER_OBJ}

aclUser :: AclTagT
aclUser = #{const ACL_USER}

aclGroupObj :: AclTagT
aclGroupObj = #{const ACL_GROUP_OBJ}

aclGroup :: AclTagT
aclGroup = #{const ACL_GROUP}

aclMask :: AclTagT
aclMask = #{const ACL_MASK}

aclOther :: AclTagT
aclOther = #{const ACL_OTHER}


aclTypeAccess :: AclTypeT
aclTypeAccess = #{const ACL_TYPE_ACCESS}

aclTypeDefault :: AclTypeT
aclTypeDefault = #{const ACL_TYPE_DEFAULT}


aclUndefinedId :: Num a => a
aclUndefinedId = #{const ACL_UNDEFINED_ID}


newtype ACL = ACL (ForeignPtr ACL)
type AclT = Ptr ACL

newtype Entry = Entry (ForeignPtr Entry)
type AclEntryT = Ptr Entry


newtype Permset = Permset (ForeignPtr Permset)
type AclPermsetT = Ptr Permset

aclFirstEntry :: Num a => a
aclFirstEntry = #{const ACL_FIRST_ENTRY}

aclNextEntry :: Num a => a
aclNextEntry = #{const ACL_NEXT_ENTRY}



foreign import ccall unsafe acl_dup :: AclT -> IO AclT

foreign import ccall unsafe acl_free :: Ptr () -> IO CInt

foreign import ccall unsafe acl_init :: CInt -> IO AclT



foreign import ccall unsafe acl_copy_entry :: AclEntryT -> AclEntryT -> IO CInt

foreign import ccall unsafe acl_create_entry :: Ptr AclT -> Ptr AclEntryT
                                             -> IO CInt

foreign import ccall unsafe acl_delete_entry :: AclT -> AclEntryT -> IO CInt

foreign import ccall unsafe acl_get_entry :: AclT -> CInt -> Ptr AclEntryT
                                          -> IO CInt

foreign import ccall unsafe acl_valid :: AclT -> IO CInt


foreign import ccall unsafe acl_add_perm :: AclPermsetT -> AclPermT -> IO CInt

foreign import ccall unsafe acl_calc_mask :: Ptr AclT -> IO CInt

foreign import ccall unsafe acl_clear_perms :: AclPermsetT -> IO CInt

foreign import ccall unsafe acl_delete_perm :: AclPermsetT -> AclPermT
                                            -> IO CInt

foreign import ccall unsafe acl_get_permset :: AclEntryT -> Ptr AclPermsetT
                                            -> IO CInt

foreign import ccall unsafe acl_set_permset :: AclEntryT -> AclPermsetT
                                            -> IO CInt


foreign import ccall unsafe acl_get_qualifier :: AclEntryT -> IO (Ptr ())

foreign import ccall unsafe acl_get_tag_type :: AclEntryT -> Ptr AclTagT
                                             -> IO CInt

foreign import ccall unsafe acl_set_qualifier :: AclEntryT -> Ptr () -> IO CInt

foreign import ccall unsafe acl_set_tag_type :: AclEntryT -> AclTagT -> IO CInt



foreign import ccall unsafe acl_delete_def_file :: CString -> IO CInt

foreign import ccall unsafe acl_get_fd :: CInt -> IO AclT

foreign import ccall unsafe acl_get_file :: CString -> AclTypeT -> IO AclT

foreign import ccall unsafe acl_set_fd :: CInt -> AclT -> IO CInt

foreign import ccall unsafe acl_set_file :: CString -> AclTypeT -> AclT
                                         -> IO CInt



foreign import ccall unsafe acl_copy_ext :: Ptr () -> AclT -> CSsize
                                         -> IO CSsize

foreign import ccall unsafe acl_copy_int :: Ptr () -> IO AclT

foreign import ccall unsafe acl_from_text :: CString -> IO AclT

foreign import ccall unsafe acl_size :: AclT -> IO CSsize

foreign import ccall unsafe acl_to_text :: AclT -> Ptr CSsize -> IO CString
