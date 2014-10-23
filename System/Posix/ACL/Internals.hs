{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE MultiWayIf                 #-}
{-# LANGUAGE Trustworthy                #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE UndecidableInstances       #-}

-- | We do not export this module because the functions
-- @'createEntry'@ and @'calcMask'@ are not safe as they can possibly
-- free their @'ACL'@ argument (see below).
module System.Posix.ACL.Internals
    ( -- *Data structures
      Perm(..)
    , Type(..)
    , Tag(..)
    , AclT
    , EntryT
    , PermsetT

    -- *Working with ACLs
    , runNewAclT, runDupAclT
    , runEntryT, getEntries, getEntry

    , copyEntry
    , deleteEntry
    , valid

    , changePermset
    , addPerm
    , calcMask
    , clearPerms
    , deletePerm

    , getTag, setTag

    -- *Get, set and delete ACL from file
    , deleteDefaultACL
    , getFdACL
    , getFileACL
    , setFdACL
    , setFileACL

    -- *ACL internal/external representation
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
         | User UserID
         | GroupObj
         | Group GroupID
         | Mask
         | Other
         | Undefined
           deriving (Eq, Read, Show)



aclFree :: Ptr a -> IO ()
aclFree = throwErrnoIfMinus1_ "acl_free" . acl_free . castPtr


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

runNewAclT :: MonadBaseControl IO m => Int -> AclT m a -> m a
runNewAclT = runAclT . throwErrnoIfNull "acl_init" . acl_init . fromIntegral

runDupAclT :: MonadBaseControl IO m => AclT m a -> AclT m a
runDupAclT aclt =
    AclT $ ReaderT $ \p ->
        runAclT (peek p >>= (throwErrnoIfNull "acl_dup" . acl_dup)) aclt

runFromExtAclT :: MonadBaseControl IO m => ExtRepr -> AclT m a -> m a
runFromExtAclT (ExtRepr bs) =
    runAclT $ unsafeUseAsCStringLen bs $
            throwErrnoIfNull "acl_copy_int" . acl_copy_int . castPtr . fst

runFromTextAclT :: MonadBaseControl IO m => String -> AclT m a -> m a
runFromTextAclT str =
    runAclT $ withCString str $ throwErrnoIfNull "acl_from_text" . acl_from_text


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

getEntry :: MonadBase IO m => Int -> EntryT m a -> AclT m a
getEntry n ent =
    (!!n) <$> runListT (getEntries (replicate n (return undefined) ++ [ent]))

deleteEntry :: MonadBase IO m => EntryT m ()
deleteEntry =
    EntryT $ ReaderT $ \(entry, acl) -> liftBase $
    throwErrnoIfMinus1_ "acl_delete_entry" $ acl_delete_entry acl entry


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

addPerm :: MonadBase IO m => Perm -> PermsetT m ()
addPerm perm =
    PermsetT $ ReaderT $ \ps ->
        liftBase $ throwErrnoIfMinus1_ "acl_add_perm" $ acl_add_perm ps $
                 fromPerm perm

clearPerms :: MonadBase IO m => PermsetT m ()
clearPerms =
    PermsetT $ ReaderT $
    liftBase . throwErrnoIfMinus1_ "acl_clear_perms" . acl_clear_perms

deletePerm :: MonadBase IO m => Perm -> PermsetT m ()
deletePerm perm =
    PermsetT $ ReaderT $ \ps ->
        liftBase $ throwErrnoIfMinus1_ "acl_delete_perm" $ acl_delete_perm ps $
                 fromPerm perm

-- | Return @'False'@ if the argument is not a valid ACL.
valid :: MonadBase IO m => AclT m Bool
valid =
    AclT $ ReaderT $ liftBase .
             (peek >=> fmap (== 0) . acl_valid)

-- | Frees and reallocate the @'ACL'@ when there there is not enough
-- space inside it to allocate the mask.
calcMask :: MonadBase IO m => AclT m ()
calcMask =
    AclT $ ReaderT $
         liftBase . mask_ . throwErrnoIfMinus1_ "acl_calc_mask" . acl_calc_mask

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


newtype ExtRepr = ExtRepr ByteString
    deriving Eq

instance Show ExtRepr where
    show (ExtRepr bs) = unpack bs

copyExt :: MonadBase IO m => AclT m ExtRepr
copyExt =
    AclT $ ReaderT $ \p -> liftBase $
        do acl <- peek p
           s <- throwErrnoIfMinus1 "acl_size" $ acl_size acl
           allocaBytes (fromIntegral s) $ \q ->
               do throwErrnoIfMinus1_ "acl_copy_ext" $ acl_copy_ext q acl s
                  ExtRepr <$> packCStringLen (castPtr q,fromIntegral s)


-- | Return the long text descripion of an @'ACL'@.
toText :: MonadBase IO m => AclT m String
toText =
    AclT $ ReaderT $ \p -> liftBase $
        do acl <- peek p
           alloca $ \q ->
               bracket (throwErrnoIfNull "acl_to_text" $ acl_to_text acl q)
               aclFree
               (\cstr -> do size <- peek q
                            peekCStringLen (cstr, fromIntegral size))


getFileACL :: MonadBaseControl IO m => FilePath -> Type -> AclT m a -> m a
getFileACL path typ =
    runAclT (withCString path $ \x ->
             throwErrnoIfNull "acl_get_file" (acl_get_file x (fromType typ)))

getFdACL :: MonadBaseControl IO m => Fd -> AclT m a -> m a
getFdACL (Fd n) =
    runAclT $ throwErrnoIfNull "acl_get_fd" $ acl_get_fd n

setFdACL :: MonadBase IO m => Fd -> AclT m ()
setFdACL (Fd n) =
    AclT $ ReaderT $
         liftBase . (peek >=> throwErrnoIfMinus1_ "acl_set_fd" . acl_set_fd n)

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
