-- | We do not export this module because the functions
-- @'createEntry'@ and @'calcMask'@ are not safe as they can possibly
-- free their @'ACL'@ argument (see below).
module System.Posix.ACL.Internals
    ( -- *Data structures
      Perm(..)
    , Type(..)
    , Tag(..)
    , ACL
    , Entry
    , Permset
    , permsetToIntegral
    , Qualifier(..)

    -- *Allocate ACL
    , newACL
    , duplicate
--   , aclFree


    , copyEntry
    , createEntry
    , deleteEntry
    , getEntries
    , valid

    , addPerm
    , calcMask
    , clearPerms
    , deletePerm
    , getPermset
    , setPermset

    , getTagType
    , setTagType
    , getQualifier
    , setQualifier

    -- *Get, set and delete ACL from file
    , deleteDefaultACL
    , getFdACL
    , getFileACL
    , setFdACL
    , setFileACL

    -- *ACL to and from text
    , fromText
    , toText

    -- *ACL internal/external representation
--    , ExtRepr
--    , size
--    , copyExt
--    , copyInt

    ) where

--import Data.ByteString
import           Control.Applicative    ((<$>))
import           Foreign
import           Foreign.C
import qualified Foreign.Concurrent
import           System.Posix.ACL.Acl_h
import           System.Posix.Types     (Fd (..), GroupID, UserID)



data Perm = Read
          | Write
          | Execute
            deriving (Eq, Read, Show)

fromPerm :: Perm -> AclPermT
fromPerm Read    = aclRead
fromPerm Write   = aclWrite
fromPerm Execute = aclExecute


data Type = Access
          | Default
            deriving (Eq, Read, Show)

fromType :: Type -> AclTypeT
fromType Access  = aclTypeAccess
fromType Default = aclTypeDefault

data Tag = UserObj
         | User
         | GroupObj
         | Group
         | Mask
         | Other
         | Undefined
           deriving (Eq, Read, Show)

fromTag :: Tag -> AclTagT
fromTag UserObj   = aclUserObj
fromTag User      = aclUser
fromTag GroupObj  = aclGroupObj
fromTag Group     = aclGroup
fromTag Mask      = aclMask
fromTag Other     = aclOther
fromTag Undefined = aclUndefinedTag

toTag :: AclTagT -> Tag
toTag t | t == aclUserObj      = UserObj
        | t == aclUser         = User
        | t == aclGroupObj     = GroupObj
        | t == aclGroup        = Group
        | t == aclMask         = Mask
        | t == aclOther        = Other
        | t == aclUndefinedTag = Undefined
        | otherwise            = error "not a valid ACL tag type"

data Qualifier = UserID UserID
               | GroupID GroupID
                 deriving (Eq, Show, Read)



aclFree :: Ptr a -> IO ()
aclFree ptr = throwErrnoIfMinus1_ "acl_free" (acl_free (castPtr ptr))

newACLPtr :: Ptr a -> IO (ForeignPtr a)
newACLPtr p = Foreign.Concurrent.newForeignPtr p (aclFree p)


withACL :: ACL -> (AclT -> IO b) -> IO b
withACL (ACL p) = withForeignPtr p

toACL :: AclT -> IO ACL
toACL p = ACL <$> newACLPtr p


withEntry :: Entry -> (AclEntryT -> IO b) -> IO b
withEntry (Entry p) = withForeignPtr p

toEntry :: AclEntryT -> IO Entry
toEntry p = Entry <$> newACLPtr p


withPermset :: Permset -> (AclPermsetT -> IO b) -> IO b
withPermset (Permset p) = withForeignPtr p

toPermset :: AclPermsetT -> IO Permset
toPermset p = Permset <$> newACLPtr p

permsetToCUInt :: Permset -> IO CUInt
permsetToCUInt p = withPermset p (peek . castPtr)

permsetToIntegral ::  Integral a => Permset -> IO a
permsetToIntegral p = fromIntegral <$> permsetToCUInt p

peekAndThrowErrnoIfNull :: String -> (Ptr a -> IO b) -> Ptr a -> IO b
peekAndThrowErrnoIfNull str fun ptr =
  if ptr == nullPtr
  then throwErrno str
  else fun ptr


-- | @'newACL' n@ allocates an ACL of at least @n@ entries.
newACL :: Int -> IO ACL
newACL n =
    acl_init (fromIntegral n) >>= peekAndThrowErrnoIfNull "acl_init" toACL

-- | Return a copy of the original ACL.
duplicate :: ACL -> IO ACL
duplicate acl =
    withACL acl acl_dup >>= peekAndThrowErrnoIfNull "acl_dup" toACL


-- | Copy the first ACL entry into the second.
copyEntry :: Entry -> Entry -> IO ()
copyEntry dest src = throwErrnoIfMinus1_ "acl_copy_entry"
                     (withEntry dest (withEntry src . acl_copy_entry))

-- | Throws an exception if the argument is not a valic ACL.
valid :: ACL -> IO ()
valid acl =
    withACL acl (throwErrnoIfMinus1_ "acl_valid" . acl_valid)


withAlloc :: (Storable a) => (Ptr a -> IO b) -> IO (a, b)
withAlloc fun =
  alloca $ \p -> do ret <- fun p
                    val <- peek p
                    return (val,ret)

-- | Frees and reallocate the @'ACL'@ when there is not
-- enough space inside it to create the new @'Entry'@.
createEntry :: ACL -> IO Entry
createEntry acl =
  withACL acl $ \x ->
      with x $ \p ->
          withAlloc (throwErrnoIfMinus1 "acl_create_entry" . acl_create_entry p)
  >>= toEntry . fst

-- | Remove an ACL entry from an ACL.
deleteEntry :: ACL -> Entry -> IO ()
deleteEntry acl ent =
    withACL acl $ \x ->
        withEntry ent (throwErrnoIfMinus1_ "acl_delete_entry"
                       . acl_delete_entry x)

-- | Get the list of entries in an ACL.
getEntries :: ACL -> IO [Entry]
getEntries acl = do
  may <- getFirstEntry acl
  case may of
    Nothing  -> return []
    Just ent -> do ents <- getNextEntries acl
                   return (ent:ents)
    where getNextEntries a = do m <- getNextEntry a
                                case m of
                                  Nothing -> return []
                                  Just e  -> do es <- getNextEntries a
                                                return (e:es)

getFirstEntry :: ACL -> IO (Maybe Entry)
getFirstEntry acl = getEntry acl aclFirstEntry

getNextEntry :: ACL -> IO (Maybe Entry)
getNextEntry acl = getEntry acl aclNextEntry

getEntry :: ACL -> CInt -> IO (Maybe Entry)
getEntry acl n = do
  (en,r) <- withACL acl $ \x -> withAlloc (acl_get_entry x n)
  case r of
    (-1) -> throwErrno "acl_get_entry"
    0    -> return Nothing
    1    -> Just <$> toEntry en
    _    -> throwErrno "acl_get_entry"


-- | Add the permission @'Perm'@ to a permission set.
addPerm :: Permset -> Perm -> IO ()
addPerm perms perm =
    withPermset perms $ \x ->
        throwErrnoIfMinus1_ "acl_add_perm" (acl_add_perm x (fromPerm perm))

-- | Frees and reallocate the @'ACL'@ when there there is not enough
-- space inside it to allocate the mask.
calcMask :: ACL -> IO ()
calcMask acl =
    withACL acl $ \x ->
        with x (throwErrnoIfMinus1_ "acl_calc_mask" . acl_calc_mask)

clearPerms :: Permset -> IO ()
clearPerms perms =
    withPermset perms (throwErrnoIfMinus1_ "acl_clear_perms" . acl_clear_perms)

-- | Delete the permission @'Perm'@ from a permission set.
deletePerm :: Permset -> Perm -> IO ()
deletePerm perms perm =
    withPermset perms $ \x ->
        throwErrnoIfMinus1_ "acl_delete_perm" $
        acl_delete_perm x (fromPerm perm)

getPermset :: Entry -> IO Permset
getPermset ent =
  withEntry ent $ \x ->
      withAlloc (throwErrnoIfMinus1 "acl_get_permset" . acl_get_permset x)
  >>= (toPermset . fst)

setPermset :: Entry -> Permset -> IO ()
setPermset ent perms =
    withEntry ent $ \x ->
        withPermset perms (throwErrnoIfMinus1_ "acl_set_permset"
                           . acl_set_permset x)

getTagType :: Entry -> IO Tag
getTagType ent =
 (toTag . fst) <$>
 withEntry ent (\x ->
                withAlloc (throwErrnoIfMinus1 "acl_get_tag_type"
                           . acl_get_tag_type x))

setTagType :: Entry -> Tag -> IO ()
setTagType ent tag =
    withEntry ent $ \x ->
        throwErrnoIfMinus1_ "acl_set_tag_type" (acl_set_tag_type x
                                                (fromTag tag))

getQualifier :: Entry -> IO (Maybe Qualifier)
getQualifier ent = do
  tag <- getTagType ent
  case tag of
    User  -> do q <- getQual
                if q == nullPtr
                then throwErrno "acl_get_qualifier"
                else do qual <- peek (castPtr q)
                        aclFree q
                        return $ Just (UserID qual)
    Group -> do q <- getQual
                if q == nullPtr
                then throwErrno "acl_get_qualifier"
                else do qual <- peek (castPtr q)
                        aclFree q
                        return $ Just (GroupID qual)
    _     -> return Nothing
    where getQual = withEntry ent acl_get_qualifier

setQualifier :: Entry -> Qualifier -> IO ()
setQualifier ent qual =
    case qual of
      UserID uid  -> setQual uid
      GroupID gid -> setQual gid
    where setQual i =
              withEntry ent $ \x ->
                  with i $ \p ->
                      throwErrnoIfMinus1_
                      "acl_set_qualifier" (acl_set_qualifier x $ castPtr p)

{-
newtype ExtRepr = ExtRepr ByteString
    deriving (Eq, Show)

size :: ExtRepr -> Int
size (ExtRepr b) = Data.ByteString.length b

copyExt :: ACL -> IO ExtRepr
copyExt acl = withACL acl $
              \x -> do
                s <- throwErrnoIfMinus1 "acl_size" (acl_size x)
                allocaBytes (fromIntegral s) $
                    \p -> do
                      throwErrnoIfMinus1_ "acl_copy_ext" $
                          acl_copy_ext p x s
                      b <- packCStringLen (castPtr p,fromIntegral s)
                      return $ ExtRepr b

copyInt :: ExtRepr -> IO ACL
copyInt (ExtRepr b) = useAsCStringLen b $ \(p,_) -> do
                        q <- acl_copy_int (castPtr p)
                        peekAndThrowErrnoIfNull "acl_copy_int" toACL q
-}
fromText :: String -> IO ACL
fromText str = do
  p <- withCString str acl_from_text
  if p == nullPtr
  then throwErrno "acl_from_text"
  else toACL p

-- | Return the long text descripion of an @'ACL'@.
toText :: ACL -> IO String
toText acl = do
  cstr <- withACL acl (`acl_to_text` nullPtr)
  if cstr == nullPtr
  then throwErrno "acl_to_text"
  else do str <- peekCString cstr
          aclFree cstr
          return str


getFileACL :: FilePath -> Type -> IO ACL
getFileACL path typ =  do
  p <- withCString path $ \x ->
       throwErrnoIfNull "acl_get_file" (acl_get_file x (fromType typ))
  toACL p

getFdACL :: Fd -> IO ACL
getFdACL (Fd n) = throwErrnoIfNull "acl_get_fd" (acl_get_fd n) >>= toACL

setFdACL :: Fd -> ACL -> IO ()
setFdACL (Fd n) acl =
    withACL acl (throwErrnoIfMinus1_ "acl_set_fd" . acl_set_fd n)

setFileACL :: FilePath -> Type -> ACL -> IO ()
setFileACL path typ acl =
    withCString path $ \x ->
        withACL acl (throwErrnoIfMinus1_ "acl_set_file"
                     . acl_set_file x (fromType typ))

-- | Delete the default ACL from a directory.
deleteDefaultACL :: FilePath -> IO ()
deleteDefaultACL file =
    withCString file $ \x ->
        throwErrnoIfMinus1_ "acl_delete_def_file" $ acl_delete_def_file x
