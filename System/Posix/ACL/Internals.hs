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
import Foreign
import Foreign.C
import qualified Foreign.Concurrent
import System.Posix.ACL.Acl_h
import System.Posix.Types (Fd(..), GroupID, UserID)



data Perm = Read
          | Write
          | Execute
            deriving (Eq, Read, Show)

fromPerm :: Perm -> AclPermT
fromPerm Read = cAclRead
fromPerm Write = cAclWrite
fromPerm Execute = cAclExecute


data Type = Access
          | Default
            deriving (Eq, Read, Show)

fromType :: Type -> AclTypeT
fromType Access = cAclTypeAccess
fromType Default = cAclTypeDefault

data Tag = UserObj
         | User
         | GroupObj
         | Group
         | Mask
         | Other
         | Undefined
           deriving (Eq, Read, Show)

instance Enum Tag where
    fromEnum Undefined = fromIntegral cAclUndefinedTag
    fromEnum UserObj = fromIntegral cAclUserObj
    fromEnum User = fromIntegral cAclUser
    fromEnum GroupObj = fromIntegral cAclGroupObj
    fromEnum Group = fromIntegral cAclGroup
    fromEnum Mask = fromIntegral cAclMask
    fromEnum Other = fromIntegral cAclOther

    toEnum n | n == (fromIntegral cAclUndefinedTag) = Undefined
             | n == (fromIntegral cAclUserObj) = UserObj
             | n == (fromIntegral cAclUser) = User
             | n == (fromIntegral cAclGroupObj) = GroupObj
             | n == (fromIntegral cAclGroup) = Group
             | n == (fromIntegral cAclMask) = Mask
             | n == (fromIntegral cAclOther) = Other
             | otherwise = error ("(Prelude.toEnum " ++ (show n) ++ ")::Tag: "
                                  ++ (show n)
                                  ++ " is outside of enumeration range")

data Qualifier = UserID UserID
               | GroupID GroupID
                 deriving (Eq, Show, Read)



cFromEnum :: (Enum e, Integral i) => e -> i
cFromEnum = fromIntegral . fromEnum

cToEnum :: (Integral i, Enum e) => i -> e
cToEnum = toEnum . fromIntegral
                 
aclFree :: Ptr a -> IO ()
aclFree ptr = throwErrnoIfMinus1_ "acl_free" (c_acl_free (castPtr ptr))

newACLPtr :: Ptr a -> IO (ForeignPtr a)
newACLPtr p = Foreign.Concurrent.newForeignPtr p (aclFree p)


withACL :: ACL -> (AclT -> IO b) -> IO b
withACL (ACL p) = withForeignPtr p

toACL :: AclT -> IO ACL
toACL p = newACLPtr p >>= return . ACL


withEntry :: Entry -> (AclEntryT -> IO b) -> IO b
withEntry (Entry p) = withForeignPtr p

toEntry :: AclEntryT -> IO Entry
toEntry p = newACLPtr p >>= return . Entry


withPermset :: Permset -> (AclPermsetT -> IO b) -> IO b
withPermset (Permset p) = withForeignPtr p

toPermset :: AclPermsetT -> IO Permset
toPermset p = newACLPtr p >>= return . Permset

permsetToCUInt :: Permset -> IO (CUInt)
permsetToCUInt p = withPermset p (peek . castPtr)

permsetToIntegral ::  Integral a => Permset -> IO a
permsetToIntegral p = permsetToCUInt p >>= return . fromIntegral

peekAndThrowErrnoIfNull :: String -> (Ptr a -> IO b) -> Ptr a -> IO b
peekAndThrowErrnoIfNull str fun ptr = do
  if ptr == nullPtr
    then throwErrno str
    else fun ptr


-- | @'newACL' n@ allocates an ACL of at least @n@ entries.
newACL :: Int -> IO ACL
newACL n = c_acl_init (fromIntegral n)
           >>= peekAndThrowErrnoIfNull "acl_init" toACL

-- | Return a copy of the original ACL.
duplicate :: ACL -> IO ACL
duplicate acl = withACL acl c_acl_dup
                >>= peekAndThrowErrnoIfNull "acl_dup" toACL


-- | Copy the first ACL entry into the second.
copyEntry :: Entry -> Entry -> IO ()
copyEntry dest src = throwErrnoIfMinus1_ "acl_copy_entry"
                     (withEntry dest (\x ->
                                          withEntry src (\y ->
                                                         c_acl_copy_entry x y
                                                        )
                                     )
                     )

-- | Throws an exception if the argument is not a valic ACL.
valid :: ACL -> IO ()
valid acl =
    withACL acl (\x -> throwErrnoIfMinus1_ "acl_valid" (c_acl_valid x))


withAlloc :: (Storable a) => (Ptr a -> IO b) -> IO (a, b)
withAlloc fun  = do
  alloca $ \p -> do ret <- fun p
                    val <- peek p
                    return (val,ret)

-- | Frees and reallocate the @'ACL'@ when there is not
-- enough space inside it to create the new @'Entry'@.
createEntry :: ACL -> IO Entry
createEntry acl = do
  (en, _) <- withACL acl (\x ->
                          (with x (\p ->
                                   (withAlloc (\y -> throwErrnoIfMinus1 
                                                     "acl_create_entry"
                                                     (c_acl_create_entry p y)
                                              )
                                   )
                                  )
                          )
                         )

  toEntry en >>= return

-- | Remove an ACL entry from an ACL.
deleteEntry :: ACL -> Entry -> IO ()
deleteEntry acl ent = withACL acl (\x ->
                                   withEntry ent (\y ->
                                                  throwErrnoIfMinus1_
                                                  "acl_delete_entry"
                                                  (c_acl_delete_entry x y)
                                                 )
                                  )

-- | Get the list of entries in an ACL.
getEntries :: ACL -> IO [Entry]
getEntries acl = do
  may <- getFirstEntry acl
  case may of
    Nothing -> return []
    Just ent -> do
           ents <- getNextEntries acl
           return (ent:ents)
        where getNextEntries a = do
                   m <- getNextEntry a
                   case m of
                     Nothing -> return []
                     Just e -> do
                            es <- getNextEntries a
                            return (e:es)

getFirstEntry :: ACL -> IO (Maybe Entry)
getFirstEntry acl = getEntry acl cAclFirstEntry

getNextEntry :: ACL -> IO (Maybe Entry)
getNextEntry acl = getEntry acl cAclNextEntry

getEntry :: ACL -> CInt -> IO (Maybe Entry)
getEntry acl n = do
  (en,r) <- withACL acl (\x -> withAlloc (\y -> c_acl_get_entry x n y))
  case r of
    (-1) -> throwErrno "acl_get_entry"
    0 -> return Nothing
    1 -> toEntry en >>= return . Just
    _ -> throwErrno "acl_get_entry"
                                    

-- | Add the permission @'Perm'@ to a permission set.
addPerm :: Permset -> Perm -> IO ()
addPerm perms perm = withPermset perms (\x ->
                                          throwErrnoIfMinus1_
                                          "acl_add_perm"
                                          (c_acl_add_perm x (fromPerm perm))
                                       )

-- | Frees and reallocate the @'ACL'@ when there there is not enough
-- space inside it to allocate the mask.
calcMask :: ACL -> IO ()
calcMask acl = withACL acl (\x ->
                                with x (\p ->
                                            throwErrnoIfMinus1_
                                            "acl_calc_mask"
                                            (c_acl_calc_mask p)
                                       )
                           )

clearPerms :: Permset -> IO ()
clearPerms perms = withPermset perms (\x ->
                                          throwErrnoIfMinus1_
                                          "acl_clear_perms"
                                          (c_acl_clear_perms x)
                                     )

-- | Delete the permission @'Perm'@ from a permission set.
deletePerm :: Permset -> Perm -> IO ()
deletePerm perms perm = withPermset perms (\x ->
                                           throwErrnoIfMinus1_
                                           "acl_delete_perm"
                                           (c_acl_delete_perm x (fromPerm perm))
                                          )

getPermset :: Entry -> IO Permset
getPermset ent = do
  (perms, _) <- withEntry ent (\x ->
                                   withAlloc (\p ->
                                                  throwErrnoIfMinus1
                                                  "acl_get_permset"
                                                  (c_acl_get_permset x p)
                                             )
                              )
  toPermset perms >>= return

setPermset :: Entry -> Permset -> IO ()
setPermset ent perms = withEntry ent (\x ->
                                      withPermset perms (\y ->
                                                         throwErrnoIfMinus1_
                                                         "acl_set_permset"
                                                         (c_acl_set_permset x y)
                                                        )
                                     )

getTagType :: Entry -> IO Tag
getTagType ent = do
  (t, _) <- withEntry ent (\x ->
                           withAlloc (\y ->
                                      throwErrnoIfMinus1 "acl_get_tag_type"
                                                         (c_acl_get_tag_type x y)
                                     )
                          )
  return $ cToEnum t

setTagType :: Entry -> Tag -> IO ()
setTagType ent tag = withEntry ent (\x ->
                                        throwErrnoIfMinus1_
                                        "acl_set_tag_type"
                                        (c_acl_set_tag_type x (cFromEnum tag))
                                   )

getQualifier :: Entry -> IO (Maybe Qualifier)
getQualifier ent = do
  tag <- getTagType ent
  case tag of
    User -> do
             q <- getQual
             if q == nullPtr
               then throwErrno "acl_get_qualifier"
               else do qual <- peek (castPtr q)
                       aclFree q
                       return $ Just (UserID qual)
    Group -> do
             q <- getQual
             if q == nullPtr
               then throwErrno "acl_get_qualifier"
               else do qual <- peek (castPtr q)
                       aclFree q
                       return $ Just (GroupID qual)
    _     -> return Nothing
    where getQual = withEntry ent (\x -> c_acl_get_qualifier x)

setQualifier :: Entry -> Qualifier -> IO ()
setQualifier ent qual = case qual of
                          UserID uid -> setQual uid
                          GroupID gid -> setQual gid
    where setQual i = withEntry ent (\x ->
                                         with i (\p ->
                                                     throwErrnoIfMinus1_
                                                     "acl_set_qualifier"
                                                     (c_acl_set_qualifier x $ castPtr p)
                                                 
                                                 )
                                    )
{-
newtype ExtRepr = ExtRepr ByteString
    deriving (Eq, Show)

size :: ExtRepr -> Int
size (ExtRepr b) = Data.ByteString.length b

copyExt :: ACL -> IO ExtRepr
copyExt acl = withACL acl $
              \x -> do
                s <- throwErrnoIfMinus1 "acl_size" (c_acl_size x)
                allocaBytes (fromIntegral s) $
                    \p -> do
                      throwErrnoIfMinus1_ "acl_copy_ext" $
                          c_acl_copy_ext p x s
                      b <- packCStringLen (castPtr p,fromIntegral s)
                      return $ ExtRepr b

copyInt :: ExtRepr -> IO ACL
copyInt (ExtRepr b) = useAsCStringLen b $ \(p,_) -> do
                        q <- c_acl_copy_int (castPtr p)
                        peekAndThrowErrnoIfNull "acl_copy_int" toACL q
-}
fromText :: String -> IO ACL
fromText str = do
  p <- withCString str (\x -> c_acl_from_text x)
  if p == nullPtr
    then throwErrno "acl_from_text"
    else toACL p

-- | Return the long text descripion of an @'ACL'@.
toText :: ACL -> IO (String)
toText acl = do
  cstr <- withACL acl (\x -> c_acl_to_text x nullPtr)
  if cstr == nullPtr
    then throwErrno "acl_to_text"
    else do str <- peekCString cstr
            aclFree cstr
            return str


getFileACL :: FilePath -> Type -> IO (ACL)
getFileACL path typ =  do
  p <- withCString path (\x ->
                             throwErrnoIfNull "acl_get_file" $
                                              c_acl_get_file x (fromType typ))
  toACL p

getFdACL :: Fd -> IO (ACL)
getFdACL (Fd n) = do
  p <- throwErrnoIfNull "acl_get_fd" (c_acl_get_fd n)
  toACL p

setFdACL :: Fd -> ACL -> IO ()
setFdACL (Fd n) acl = withACL acl (\x ->
                                       throwErrnoIfMinus1_ "acl_set_fd" $
                                                           c_acl_set_fd n x)

setFileACL :: FilePath -> Type -> ACL -> IO ()
setFileACL path typ acl = withCString path (\x -> withACL acl
                                                  (\y -> throwErrnoIfMinus1_
                                                         "acl_set_file"
                                                         (c_acl_set_file x (fromType typ) y)))

-- | Delete the default ACL from a directory.
deleteDefaultACL :: FilePath -> IO ()
deleteDefaultACL file = withCString file $
                        \x ->
                        throwErrnoIfMinus1_ "acl_delete_def_file" $
                                            c_acl_delete_def_file x
