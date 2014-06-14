{-# LANGUAGE ForeignFunctionInterface #-}

module System.Posix.ACL.Acl_h where

import           Foreign
import           Foreign.C
import           System.Posix.Types (CSsize (..))

#include <sys/acl.h>

type AclTypeT = #{type acl_type_t}
type AclTagT = #{type acl_tag_t}
type AclPermT = #{type acl_perm_t}

cAclRead :: AclPermT
cAclRead = #{const ACL_READ}

cAclWrite :: AclPermT
cAclWrite = #{const ACL_WRITE}

cAclExecute :: AclPermT
cAclExecute = #{const ACL_EXECUTE}


cAclUndefinedTag :: AclTagT
cAclUndefinedTag = #{const ACL_UNDEFINED_TAG}

cAclUserObj :: AclTagT
cAclUserObj = #{const ACL_USER_OBJ}

cAclUser :: AclTagT
cAclUser = #{const ACL_USER}

cAclGroupObj :: AclTagT
cAclGroupObj = #{const ACL_GROUP_OBJ}

cAclGroup :: AclTagT
cAclGroup = #{const ACL_GROUP}

cAclMask :: AclTagT
cAclMask = #{const ACL_MASK}

cAclOther :: AclTagT
cAclOther = #{const ACL_OTHER}


cAclTypeAccess :: AclTypeT
cAclTypeAccess = #{const ACL_TYPE_ACCESS}

cAclTypeDefault :: AclTypeT
cAclTypeDefault = #{const ACL_TYPE_DEFAULT}


newtype ACL = ACL (ForeignPtr ACL)
type AclT = Ptr ACL

newtype Entry = Entry (ForeignPtr Entry)
type AclEntryT = Ptr Entry


newtype Permset = Permset (ForeignPtr Permset)
type AclPermsetT = Ptr Permset

cAclFirstEntry :: Num a => a
cAclFirstEntry = #{const ACL_FIRST_ENTRY}

cAclNextEntry :: Num a => a
cAclNextEntry = #{const ACL_NEXT_ENTRY}

foreign import ccall unsafe "acl_init"
  c_acl_init :: CInt -> IO AclT

foreign import ccall unsafe "acl_dup"
  c_acl_dup :: AclT -> IO AclT

foreign import ccall unsafe "acl_free"
  c_acl_free :: Ptr () -> IO CInt

-- For ForeignPtr
foreign import ccall "wrapper"
  mkFinalizerPtr :: (Ptr a -> IO ()) -> IO (FinalizerPtr a)
--

foreign import ccall unsafe "acl_valid"
  c_acl_valid :: AclT -> IO CInt

foreign import ccall unsafe "acl_copy_entry"
  c_acl_copy_entry :: AclEntryT -> AclEntryT -> IO CInt

foreign import ccall unsafe "acl_create_entry"
  c_acl_create_entry :: Ptr AclT -> Ptr AclEntryT -> IO CInt

foreign import ccall unsafe "acl_delete_entry"
  c_acl_delete_entry :: AclT -> AclEntryT -> IO CInt

foreign import ccall unsafe "acl_get_entry"
  c_acl_get_entry :: AclT -> CInt -> Ptr AclEntryT -> IO CInt

foreign import ccall unsafe "acl_add_perm"
  c_acl_add_perm :: AclPermsetT -> AclPermT -> IO CInt

foreign import ccall unsafe "acl_calc_mask"
  c_acl_calc_mask :: Ptr AclT -> IO CInt

foreign import ccall unsafe "acl_clear_perms"
  c_acl_clear_perms :: AclPermsetT -> IO CInt

foreign import ccall unsafe "acl_delete_perm"
  c_acl_delete_perm :: AclPermsetT -> AclPermT -> IO CInt

foreign import ccall unsafe "acl_get_permset"
  c_acl_get_permset :: AclEntryT -> Ptr AclPermsetT -> IO CInt

foreign import ccall unsafe "acl_set_permset"
  c_acl_set_permset :: AclEntryT -> AclPermsetT -> IO CInt

foreign import ccall unsafe "acl_get_qualifier"
  c_acl_get_qualifier :: AclEntryT -> IO (Ptr ())

foreign import ccall unsafe "acl_get_tag_type"
  c_acl_get_tag_type :: AclEntryT -> Ptr AclTagT -> IO CInt

foreign import ccall unsafe "acl_set_qualifier"
  c_acl_set_qualifier :: AclEntryT -> Ptr () -> IO CInt

foreign import ccall unsafe "acl_set_tag_type"
  c_acl_set_tag_type :: AclEntryT -> AclTagT -> IO CInt

foreign import ccall unsafe "acl_copy_ext"
  c_acl_copy_ext :: Ptr () -> AclT -> CSsize -> IO CSsize

foreign import ccall unsafe "acl_copy_int"
  c_acl_copy_int :: Ptr () -> IO AclT

foreign import ccall unsafe "acl_from_text"
  c_acl_from_text :: CString -> IO AclT

foreign import ccall unsafe "acl_size"
  c_acl_size :: AclT -> IO CSsize

foreign import ccall unsafe "acl_to_text"
  c_acl_to_text :: AclT -> Ptr CSsize -> IO CString

foreign import ccall unsafe "acl_delete_def_file"
  c_acl_delete_def_file :: CString -> IO CInt

foreign import ccall unsafe "acl_get_fd"
  c_acl_get_fd :: CInt -> IO AclT

foreign import ccall unsafe "acl_get_file"
  c_acl_get_file :: CString -> AclTypeT -> IO AclT

foreign import ccall unsafe "acl_set_fd"
  c_acl_set_fd :: CInt -> AclT -> IO CInt

foreign import ccall unsafe "acl_set_file"
  c_acl_set_file :: CString -> AclTypeT -> AclT -> IO CInt
