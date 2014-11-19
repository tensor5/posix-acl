{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE MultiWayIf                 #-}
{-# LANGUAGE Trustworthy                #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE UndecidableInstances       #-}

--------------------------------------------------------------------------------
-- |
-- Module      :  $Header$
-- Copyright   :  © 2013-2014 Nicola Squartini
-- License     :  BSD3
--
-- Maintainer  :  Nicola Squartini <tensor5@gmail.com>
-- Stability   :  experimental
-- Portability :  portable
--
-- Functions in this module are bindings to the C API defined in
-- <http://users.suse.com/~agruen/acl/posix/Posix_1003.1e-990310.pdf IEEE Std 1003.1e>.
-- The design goal is to be as low level as possible without having to allocate
-- or deallocate memory, and remaining type-safe.  In order to reach this goal,
-- all pointers to opaque C structures are represented by monad transformers
-- representing actions on those pointers.  Here is the pointer to monad
-- transformer correspondence:
--
-- @
-- acl_t         \<--\> 'AclT'
-- acl_entry_t   \<--\> 'EntryT'
-- acl_permset_t \<--\> 'PermsetT'
-- @
--
-- A common usage pattern is to modify the permset of an entry inside an ACL.
-- This is done in three steps:
--
--   1. convert the @'PermsetT' m a@ modification of permset into an @'EntryT' m
--   a@ modification of entry;
--
--   2. convert the @'EntryT' m a@ into an @'AclT' m a@ modification of ACL;
--
--   3. execute the @'AclT' m a@ in the base monad @m@.
--
-- For example in
--
-- @
-- 'runFromTextAclT' "u::rw,g::r,o::r" $ 'getEntry' 0 $ 'changePermset' $ 'addPerm' 'Execute'
-- @
--
-- @'addPerm' 'Execute'@ is the @'PermsetT'@ that adds the execute permission,
-- @'changePermset'@ converts @'PermsetT'@ into @'EntryT'@, @'getEntry' 0@
-- modifies the 1st entry of the ACL according to the action contained in
-- @'EntryT'@ (thus converts @'EntryT'@ into @'AclT'@), and finally
-- @'runFromTextAclT' "u::rw,g::r,o::r"@ runs the @'AclT'@ action on the ACL
-- represented by the short text form @u::rw,g::r,o::r@.  In words, it adds
-- execute permission to the 1st entry of @u::rw,g::r,o::r@, producing
-- @u::rwx,g::r,o::r@.
--
--------------------------------------------------------------------------------

module System.Posix.ACL.Internals
    (
    -- * ACL initialization
      AclT
    , runNewAclT, runDupAclT

    -- * ACL entry manipulation
    , EntryT
    , runEntryT, getEntries, getEntry

    , copyEntry
    , deleteEntry
    , valid

    , PermsetT, Perm(..)
    , changePermset
    , addPerm
    , calcMask
    , clearPerms
    , deletePerm

    , Tag(..)
    , getTag, setTag

    -- * Get, set and delete ACLs from a file
    , Type(..)
    , deleteDefaultACL
    , getFdACL
    , getFileACL
    , setFdACL
    , setFileACL

    -- * ACL format translation
    , ExtRepr
    , copyExt
    , runFromExtAclT
    , runFromTextAclT
    , toText

    ) where

import           Control.Applicative         (Alternative, Applicative, empty,
                                              (<$>), (<*>))
import           Control.Exception.Lifted    (bracket, mask_)
import           Control.Monad               (MonadPlus, (>=>))
import           Control.Monad.Base          (MonadBase, liftBase)
import           Control.Monad.Fix           (MonadFix)
import           Control.Monad.IO.Class      (MonadIO)
import           Control.Monad.Trans.Class   (MonadTrans)
import           Control.Monad.Trans.Control
import           Control.Monad.Trans.List    (ListT (..))
import           Control.Monad.Trans.Maybe   (MaybeT (..))
import           Control.Monad.Trans.Reader  (ReaderT (..), runReaderT)
import           Data.ByteString.Char8       (ByteString, packCStringLen,
                                              unpack)
import           Data.ByteString.Unsafe      (unsafeUseAsCStringLen)
import           Foreign.C
import           Foreign.Safe
import           System.Posix.ACL.Acl_h      hiding (AclT)
import qualified System.Posix.ACL.Acl_h      as C
import           System.Posix.Types          (Fd (..), GroupID, UserID)


-- | A single permission.
data Perm = Read
          | Write
          | Execute
            deriving (Eq, Read, Show)

fromPerm :: Perm -> AclPermT
fromPerm Read    = aclRead
fromPerm Write   = aclWrite
fromPerm Execute = aclExecute


-- | The type of an ACL (see section 23.1.3 of
-- <http://users.suse.com/~agruen/acl/posix/Posix_1003.1e-990310.pdf IEEE Std 1003.1e>).
data Type = Access
          | Default
            deriving (Eq, Read, Show)

fromType :: Type -> AclTypeT
fromType Access  = aclTypeAccess
fromType Default = aclTypeDefault


-- | Tag type and qualifier of an ACL.
data Tag = UserObj
         | User { tagUserID :: UserID }
         | GroupObj
         | Group { tagGroupID :: GroupID }
         | Mask
         | Other
         | Undefined
           deriving (Eq, Read, Show)



aclFree :: Ptr a -> IO ()
aclFree = throwErrnoIfMinus1_ "acl_free" . acl_free . castPtr


-- | Action to be performed on an ACL.  The action contained in the transformer
-- @'AclT'@ can be executed in the base monad using one of the functions
-- @'runNewAclT'@, @'getFdACL'@, @'getFileACL'@, @'runFromExtAclT'@ or
-- @'runFromTextAclT'@.
newtype AclT m a = AclT { unAclT :: ReaderT (Ptr C.AclT) m a }
    deriving ( Alternative, Applicative, Functor, Monad, MonadBase b, MonadFix
             , MonadIO, MonadPlus, MonadTrans )

instance MonadTransControl AclT where
    newtype StT AclT a = StAcl { unStAcl ::  StT (ReaderT (Ptr C.AclT)) a }
    liftWith = defaultLiftWith AclT unAclT StAcl
    restoreT = defaultRestoreT AclT unStAcl

instance MonadBaseControl b m => MonadBaseControl b (AclT m) where
    newtype StM (AclT m) a = StMAcl { unStMAcl :: ComposeSt AclT m a }
    liftBaseWith = defaultLiftBaseWith StMAcl
    restoreM     = defaultRestoreM unStMAcl

runAclT :: MonadBaseControl IO m => IO C.AclT -> AclT m a -> m a
runAclT gen (AclT rd) =
    bracket (liftBase (gen >>= new))
    (\p -> liftBase $ do peek p >>= aclFree
                         free p)
    (runReaderT rd)

-- | Run the given action on a newly created ACL with @n@ entries.
runNewAclT :: MonadBaseControl IO m => Int -> AclT m a -> m a
runNewAclT = runAclT . throwErrnoIfNull "acl_init" . acl_init . fromIntegral

-- | Create a copy of the current ACL and run the given action on the duplicate.
-- For example
--
-- @
-- 'runFromTextAclT' "u::rw,g::r,o::r" $ 'runDupAclT' ('calcMask' >> 'toText' >>= 'Control.Monad.Trans.Class.lift' . 'print') >> 'toText' >>= 'Control.Monad.Trans.Class.lift' . 'print'
-- @
--
-- copies the ACL represented by @u::rw,g::r,o::r@ to a new ACL, calculates and
-- sets the permissions of @'Mask'@ (see @'calcMask'@) in the newly created ACL
-- and prints out the result.  It also prints out the original ACL.
runDupAclT :: MonadBaseControl IO m =>
              AclT m a  -- ^ action to be run on the duplicate
           -> AclT m a
runDupAclT aclt =
    AclT $ ReaderT $ \p ->
        runAclT (peek p >>= (throwErrnoIfNull "acl_dup" . acl_dup)) aclt

-- | Run the given action on an ACL created according to the given external
-- representation.
runFromExtAclT :: MonadBaseControl IO m => ExtRepr -> AclT m a -> m a
runFromExtAclT (ExtRepr bs) =
    runAclT $ unsafeUseAsCStringLen bs $
            throwErrnoIfNull "acl_copy_int" . acl_copy_int . castPtr . fst

-- | Run the given action on an ACL created according to the given textual
-- representation (both the /Long Text Form/ and /Short Text Form/ are
-- accepted).
runFromTextAclT :: MonadBaseControl IO m => String -> AclT m a -> m a
runFromTextAclT str =
    runAclT $ withCString str $ throwErrnoIfNull "acl_from_text" . acl_from_text


-- | Action to be performed on an ACL entry.  In order to execute the action
-- contained in the @'EntryT'@ transformer in the base monad, @'EntryT'@ must
-- first be converted into @'AclT'@ using one of the functions @'runEntryT'@,
-- @'getEntries'@ or @'getEntry'@.
newtype EntryT m a = EntryT { unEntryT :: ReaderT (AclEntryT, C.AclT) m a }
    deriving ( Alternative, Applicative, Functor, Monad, MonadBase b, MonadFix
             , MonadIO, MonadPlus, MonadTrans )

instance MonadTransControl EntryT where
    newtype StT EntryT a =
        StEntry { unStEntry ::  StT (ReaderT (AclEntryT, C.AclT)) a }
    liftWith = defaultLiftWith EntryT unEntryT StEntry
    restoreT = defaultRestoreT EntryT unStEntry

instance MonadBaseControl b m => MonadBaseControl b (EntryT m) where
    newtype StM (EntryT m) a = StMEntry { unStMEntry :: ComposeSt EntryT m a }
    liftBaseWith = defaultLiftBaseWith StMEntry
    restoreM     = defaultRestoreM unStMEntry

-- | Create a new entry in the ACL an run the given action on it.
runEntryT :: MonadBase IO m => EntryT m a -> AclT m a
runEntryT (EntryT rd) =
    AclT $ ReaderT $ \p ->
        liftBase ((,) <$>
                      alloca (\q ->
                              do mask_ $
                                       throwErrnoIfMinus1_ "acl_create_entry" $
                                                           acl_create_entry p q
                                 peek q)
                  <*> peek p)
        >>= runReaderT rd


-- | Copy the contents of an ACL entry to an existing ACL entry of a possibly
-- different ACL.  For example
--
-- @
-- 'runFromTextAclT' "u::rw,u:2:rwx,g::r,m:rwx,o::r" $ 'getEntry' 1 $ 'runFromTextAclT' "u::rw,u:1:rw,u:8:rw,g::r,m:rwxo::r" ('getEntry' 2 'copyEntry' >> 'toText')
-- @
--
-- copies the 2nd entry of @u::rw,u:2:rwx,g::r,m:rwx,o::r@ (namely @u:2:rwx@)
-- into the 3rd entry of @u::rw,u:1:rw,u:8:rw,g::r,m:rwxo::r@ (namely @u:8:rw@)
-- and prints the result.
copyEntry :: MonadBase IO m => EntryT (EntryT m) ()
copyEntry =
    EntryT $ ReaderT $ \(dest, _) ->
        EntryT $ ReaderT $
               liftBase .
               throwErrnoIfMinus1_ "acl_copy_entry" . acl_copy_entry dest . fst

getEntry' :: MonadBase IO m => CInt -> EntryT m a -> MaybeT (AclT m) a
getEntry' n (EntryT rd) =
    MaybeT $ AclT $ ReaderT $ \p ->
        do acl <- liftBase $ peek p
           ment <- liftBase $ alloca $ \q ->
                   do r <- throwErrnoIfMinus1 "acl_get_entry" $
                           acl_get_entry acl n q
                      if r == 1
                      then Just <$> peek q
                      else return Nothing
           case ment of
             Nothing -> return Nothing
             Just entry -> Just <$> runReaderT rd (entry, acl)

getFirstEntry :: MonadBase IO m => EntryT m a -> MaybeT (AclT m) a
getFirstEntry = getEntry' aclFirstEntry

getNextEntry :: MonadBase IO m => EntryT m a -> MaybeT (AclT m) a
getNextEntry = getEntry' aclNextEntry

-- | Run the list of given actions on the list of entries of the ACL.
getEntries  :: MonadBase IO m => [EntryT m a] -> ListT (AclT m) a
getEntries []     = empty
getEntries (e:es) =
    ListT $ do m <- runMaybeT $ getFirstEntry e
               case m of
                 Nothing -> return []
                 Just a  -> (a:) <$> getNextEntries es
    where getNextEntries []     = return []
          getNextEntries (x:xs) =
              do m <- runMaybeT $ getNextEntry x
                 case m of
                   Nothing -> return []
                   Just a  -> (a:) <$> getNextEntries xs

-- | Run the given action on the @n@-th entry of the ACL (entry enumeration
-- begins from 0).
getEntry :: MonadBase IO m => Int -> EntryT m a -> AclT m a
getEntry n ent =
    (!!n) <$> runListT (getEntries (replicate n (return undefined) ++ [ent]))

-- | Delete the entry.
--
-- /Warning/: no further action should be performed on this entry.
deleteEntry :: MonadBase IO m => EntryT m ()
deleteEntry =
    EntryT $ ReaderT $ \(entry, acl) -> liftBase $
    throwErrnoIfMinus1_ "acl_delete_entry" $ acl_delete_entry acl entry


-- | Action to be performed on the permission set of an ACL entry.  In order to
-- execute the action contained in the @'PermsetT'@ transformer in the base
-- monad, @'PermsetT'@ must first be converted into @'EntryT'@ using
-- @'changePermset'@, and then into @'AclT'@.
newtype PermsetT m a = PermsetT { unPermsetT :: ReaderT AclPermsetT m a }
    deriving ( Alternative, Applicative, Functor, Monad, MonadBase b, MonadFix
             , MonadIO, MonadPlus, MonadTrans )

instance MonadTransControl PermsetT where
    newtype StT PermsetT a =
        StPermset { unStPermset ::  StT (ReaderT AclPermsetT) a }
    liftWith = defaultLiftWith PermsetT unPermsetT StPermset
    restoreT = defaultRestoreT PermsetT unStPermset

instance MonadBaseControl b m => MonadBaseControl b (PermsetT m) where
    newtype StM (PermsetT m) a =
        StMPermset { unStMPermset :: ComposeSt PermsetT m a }
    liftBaseWith = defaultLiftBaseWith StMPermset
    restoreM     = defaultRestoreM unStMPermset

-- | Change the permission set of the entry.
changePermset :: MonadBase IO m => PermsetT m a -> EntryT m a
changePermset (PermsetT rd) =
    EntryT $ ReaderT $ \(entry, _) ->
        do ps <- liftBase $ alloca $ \p ->
                 do throwErrnoIfMinus1_ "acl_get_permset" $
                                        acl_get_permset entry p
                    peek p
           ret <- runReaderT rd ps
           liftBase $ throwErrnoIfMinus1_ "acl_set_permset" $
                    acl_set_permset entry ps
           return ret

-- | Add a specific permission.
addPerm :: MonadBase IO m => Perm -> PermsetT m ()
addPerm perm =
    PermsetT $ ReaderT $ \ps ->
        liftBase $ throwErrnoIfMinus1_ "acl_add_perm" $ acl_add_perm ps $
                 fromPerm perm

-- | Clear all permissions from the permission set.
clearPerms :: MonadBase IO m => PermsetT m ()
clearPerms =
    PermsetT $ ReaderT $
    liftBase . throwErrnoIfMinus1_ "acl_clear_perms" . acl_clear_perms

-- | Remove a specific permission.
deletePerm :: MonadBase IO m => Perm -> PermsetT m ()
deletePerm perm =
    PermsetT $ ReaderT $ \ps ->
        liftBase $ throwErrnoIfMinus1_ "acl_delete_perm" $ acl_delete_perm ps $
                 fromPerm perm

-- | Run a validity check on the ACL (see @acl_valid()@ in section 23.4.28 of
-- <http://users.suse.com/~agruen/acl/posix/Posix_1003.1e-990310.pdf IEEE Std 1003.1e>).
valid :: MonadBase IO m => AclT m Bool
valid =
    AclT $ ReaderT $ liftBase .
             (peek >=> fmap (== 0) . acl_valid)

-- | Calculate and set the permissions associated with the @'Mask'@ ACL entry of
-- the ACL.  The value of the new permissions is the union of the permissions
-- granted by all entries of tag type @'Group'@, @'GroupObj'@, or @'User'@.  If
-- the ACL already contains a @'Mask'@ entry, its permissions are overwritten;
-- if it does not contain a @'Mask'@ entry, one is added.
calcMask :: MonadBase IO m => AclT m ()
calcMask =
    AclT $ ReaderT $
         liftBase . mask_ . throwErrnoIfMinus1_ "acl_calc_mask" . acl_calc_mask


-- | Get the entry's tag.
getTag :: MonadBase IO m => EntryT m Tag
getTag =
    EntryT $ ReaderT $ \(entry, _) -> liftBase $
    do tag <- alloca $ \p -> do throwErrnoIfMinus1_ "acl_get_tag_type" $
                                                    acl_get_tag_type entry p
                                peek p
       if | tag == aclUserObj      -> return UserObj
          | tag == aclUser         -> User <$> getQualifier entry
          | tag == aclGroupObj     -> return GroupObj
          | tag == aclGroup        -> Group <$> getQualifier entry
          | tag == aclMask         -> return Mask
          | tag == aclOther        -> return Other
          | tag == aclUndefinedTag -> return Undefined
          | otherwise              -> error "not a valid ACL tag type"
    where getQualifier e = bracket (throwErrnoIfNull "acl_get_qualifier" $
                                                     acl_get_qualifier e)
                           aclFree
                           (peek . castPtr)

-- | Set the tag of the entry.
setTag :: MonadBase IO m => Tag -> EntryT m ()
setTag tag =
    EntryT $ ReaderT $ \(entry, _) -> liftBase $
    case tag of
      UserObj   -> setTagType entry aclUserObj
      User uid  -> do setTagType entry aclUser
                      setQualifier uid entry
      GroupObj  -> setTagType entry aclGroupObj
      Group gid -> do setTagType entry aclGroup
                      setQualifier gid entry
      Mask      -> setTagType entry aclMask
      Other     -> setTagType entry aclOther
      Undefined -> setTagType entry aclUndefinedTag
    where setTagType e = throwErrnoIfMinus1_ "acl_set_tag_type" .
                         acl_set_tag_type e
          setQualifier qual e = with qual $
                                throwErrnoIfMinus1_ "acl_set_qualifier" .
                                acl_set_qualifier e . castPtr


-- | The /external representation/ of an ACL is an unspecified binary format
-- stored in a contiguous portion of memory.
newtype ExtRepr = ExtRepr ByteString
    deriving Eq

instance Show ExtRepr where
    show (ExtRepr bs) = unpack bs

-- | Return the external representation of the ACL.
copyExt :: MonadBase IO m => AclT m ExtRepr
copyExt =
    AclT $ ReaderT $ \p -> liftBase $
        do acl <- peek p
           s <- throwErrnoIfMinus1 "acl_size" $ acl_size acl
           allocaBytes (fromIntegral s) $ \q ->
               do throwErrnoIfMinus1_ "acl_copy_ext" $ acl_copy_ext q acl s
                  ExtRepr <$> packCStringLen (castPtr q,fromIntegral s)


-- | Return the /Long Text Form/ of the ACL (section 23.3.1 of
-- <http://users.suse.com/~agruen/acl/posix/Posix_1003.1e-990310.pdf IEEE Std 1003.1e>).
toText :: MonadBase IO m => AclT m String
toText =
    AclT $ ReaderT $ \p -> liftBase $
        do acl <- peek p
           alloca $ \q ->
               bracket (throwErrnoIfNull "acl_to_text" $ acl_to_text acl q)
               aclFree
               (\cstr -> do size <- peek q
                            peekCStringLen (cstr, fromIntegral size))


-- | Run the action on the ACL of type @'Type'@ of the given file.
getFileACL :: MonadBaseControl IO m => FilePath -> Type -> AclT m a -> m a
getFileACL path typ =
    runAclT (withCString path $ \x ->
             throwErrnoIfNull "acl_get_file" (acl_get_file x (fromType typ)))

-- | Run the action on the ACL of the given file descriptor.
getFdACL :: MonadBaseControl IO m => Fd -> AclT m a -> m a
getFdACL (Fd n) =
    runAclT $ throwErrnoIfNull "acl_get_fd" $ acl_get_fd n

-- | Set the ACL of the given file descriptor.
setFdACL :: MonadBase IO m => Fd -> AclT m ()
setFdACL (Fd n) =
    AclT $ ReaderT $
         liftBase . (peek >=> throwErrnoIfMinus1_ "acl_set_fd" . acl_set_fd n)

-- | Set the ACL of type @'Type'@ of the given file.
setFileACL :: MonadBase IO m => FilePath -> Type -> AclT m ()
setFileACL path typ =
    AclT $ ReaderT $ \p -> liftBase $
         do acl <- peek p
            withCString path $ \x ->
                throwErrnoIfMinus1_ "acl_set_file" $
                                    acl_set_file x (fromType typ) acl

-- | Delete the default ACL from a directory.
deleteDefaultACL :: FilePath -> IO ()
deleteDefaultACL file =
    withCString file $
                throwErrnoIfMinus1_ "acl_delete_def_file" . acl_delete_def_file
