{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE MultiParamTypeClasses #-}

-- | Support for POSIX.1e /Access Control Lists/ (ACL), defined in
-- section 23 of the draft standard IEEE Std 1003.1e.
module System.Posix.ACL
    ( Permset(..)
    , emptyPermset
    , fullPermset
    , unionPermsets
    , intersectPermsets
    , ACL(..)
    , longTextForm
    , shortTextFrom
    -- * Get and set ACLs
    , getACL
    , getDefaultACL
    , fdGetACL
    , setACL
    , setDefaultACL
    , fdSetACL
    , deleteDefaultACL
    ) where

import           Control.Applicative          ((<$>))
import           Control.Arrow                (first)
import           Control.Monad                (void, when)
import           Control.Monad.Base           (MonadBase)
import           Control.Monad.Trans.List     (ListT (..))
import           Data.List                    (find)
import           Data.Map                     hiding (map, null)
import           System.Posix.ACL.Internals
import           System.Posix.Types           (Fd, GroupID, UserID)
import           System.Posix.User
import           Text.ParserCombinators.ReadP
import           Text.Read                    hiding ((+++), (<++))


-- | A combination of read, write and execute permissions.
data Permset = Permset { hasRead    :: Bool
                       , hasWrite   :: Bool
                       , hasExecute :: Bool
                       } deriving Eq

-- | No permission.
emptyPermset :: Permset
emptyPermset = Permset False False False

-- | Read, write and execute permissions.
fullPermset :: Permset
fullPermset = Permset True True True

-- | Give a permission if any of the two arguments grant that permission.
unionPermsets :: Permset -> Permset -> Permset
unionPermsets (Permset r1 w1 e1) (Permset r2 w2 e2) =
    Permset (r1 || r2) (w1 || w2) (e1 || e2)

-- | Give a permission if both the arguments grant that permission.
intersectPermsets :: Permset -> Permset -> Permset
intersectPermsets (Permset r1 w1 e1) (Permset r2 w2 e2) =
    Permset (r1 && r2) (w1 && w2) (e1 && e2)

instance Show Permset where
    showsPrec = showsPermset

showsPermset :: Int -> Permset -> ShowS
showsPermset _ (Permset r w x) = (if r then ('r':) else ('-':)) .
                                 (if w then ('w':) else ('-':)) .
                                 (if x then ('x':) else ('-':))

showsPermsetShort :: Int -> Permset -> ShowS
showsPermsetShort _ (Permset r w x) = (if r then ('r':) else id) .
                                      (if w then ('w':) else id) .
                                      (if x then ('x':) else id)


parseRead :: ReadP Permset
parseRead = do _ <- char 'r'
               return (Permset True False False)

parseWrite :: ReadP Permset
parseWrite = do _ <- char 'w'
                return (Permset False True False)

parseExecute :: ReadP Permset
parseExecute = do _ <- char 'x'
                  return (Permset False False True)

parseDash :: ReadP Permset
parseDash = do _ <- satisfy (== '-')
               return emptyPermset

parseLongTextPermset :: ReadP Permset
parseLongTextPermset = do
  skipSpaces
  r <- parseRead +++ parseDash
  w <- parseWrite +++ parseDash
  x <- parseExecute +++ parseDash
  return (r `unionPermsets` w `unionPermsets` x)

parseShortTextPermset :: ReadP Permset
parseShortTextPermset = do
  skipSpaces
  r <- parseRead <++ return emptyPermset
  w <- parseWrite <++ return emptyPermset
  x <- parseExecute <++ return emptyPermset
  return (r `unionPermsets` w `unionPermsets` x)

parsePermset :: ReadP Permset
parsePermset = parseLongTextPermset +++ parseShortTextPermset

instance Read Permset where
    readPrec = lift parsePermset


-- | Represent a valid ACL as defined in POSIX.1e. The @'Show'@
-- instance is defined to output the /Long Text Form/ of the ACL
-- (section 23.3.1), while the @'Read'@ instance is defined to be able
-- to parse both the long and short text form.
data ACL = MinimumACL { ownerPerms       :: Permset
                      , owningGroupPerms :: Permset
                      , otherPerms       :: Permset
                      }
         | ExtendedACL { ownerPerms       :: Permset
                       , usersPerms       :: Map UserID Permset
                       , owningGroupPerms :: Permset
                       , groupsPerms      :: Map GroupID Permset
                       , mask             :: Permset
                       , otherPerms       :: Permset
                       }
           deriving Eq

instance Show ACL where
    showsPrec = showsLongText

-- | Convert an ACL to its /Long Text Form/ (see section 23.3.1 of
-- IEEE Std 1003.1e).
longTextForm :: ACL -> String
longTextForm acl = showsLongText 0 acl ""

showsLongText :: Int -> ACL -> ShowS
showsLongText n (MinimumACL ow og ot) = ("user::" ++) . showsPrec n ow .
                                        ("\ngroup::" ++) . showsPrec n og .
                                        ("\nother::" ++) . showsPrec n ot .
                                        ('\n' :)
showsLongText n (ExtendedACL ow us og gr m ot) =
    ("user::" ++) . showsPrec n ow .
    foldlWithKey showsNamedUser id us .
                     ("\ngroup::" ++) . showsPrec n og . showsEffective og .
                     foldlWithKey showsNamedGroup id gr .
                     ("\nmask::" ++) . showsPrec n m .
                     ("\nother::" ++) . showsPrec n ot .
                     ('\n' :)
    where showsNamed iD perm = showsPrec n iD . (':' :) . showsPrec n perm .
                               showsEffective perm
          showsNamedUser sh uid perm = sh . ("\nuser:" ++) . showsNamed uid perm
          showsNamedGroup sh gid perm = sh . ("\ngroup:" ++) .
                                        showsNamed gid perm
          showsEffective perm = let int = intersectPermsets m perm
                                in if int == perm
                                   then id
                                   else ("\t#effective:" ++) . showsPrec n int

-- | Convert an ACL to its /Short Text Form/ (see section 23.3.2 of
-- IEEE Std 1003.1e).
shortTextFrom :: ACL -> String
shortTextFrom acl = showsShortText 0 acl ""

showsShortText :: Int -> ACL -> ShowS
showsShortText n (MinimumACL ow og ot) = ("u::" ++) . showsPermsetShort n ow .
                                         (",g::" ++) . showsPermsetShort n og .
                                         (",o::" ++) . showsPermsetShort n ot
showsShortText n (ExtendedACL ow us og gr m ot) =
    ("u::" ++) .
    showsPermsetShort n ow .
    foldlWithKey showsNamedUser id us .
    (",g::" ++) . showsPermsetShort n og .
    foldlWithKey showsNamedGroup id gr .
    (",m::" ++) . showsPermsetShort n m .
    (",o::" ++) . showsPermsetShort n ot
    where showsNamed ident perm = showsPrec n ident . (':' :)
                                  . showsPermsetShort n perm
          showsNamedUser sh uid perm = sh . (",u:" ++) . showsNamed uid perm
          showsNamedGroup sh gid perm = sh . (",g:" ++) . showsNamed gid perm

instance Read ACL where
    readPrec = lift $ do skipSpaces
                         parseLongTextFrom [] [] +++ parseShortTextForm

parseLongTextFrom :: [UserEntry] -> [GroupEntry] -> ReadP ACL
parseLongTextFrom udb gdb =
    parseMinLongTextFrom +++ parseExtLongTextFrom udb gdb

parseMinLongTextFrom :: ReadP ACL
parseMinLongTextFrom = do
  _ <- string "user::"
  ow <- parseLongTextPermset
  _ <- string "\ngroup::"
  og <- parseLongTextPermset
  _ <- string "\nother::"
  ot <- parseLongTextPermset
  return $ MinimumACL ow og ot

resolveUser :: [UserEntry] -> String -> Maybe UserID
resolveUser db name = userID <$> find ((== name) . userName) db

resolveGroup :: [GroupEntry] -> String -> Maybe GroupID
resolveGroup db name = groupID <$> find ((== name) . groupName) db

parseUser :: [UserEntry] -> ReadP UserID
parseUser db = do name <- munch1 (/= ':')
                  case resolveUser db name of
                    Just uid -> return uid
                    Nothing  -> fail ("cannot find " ++ name ++
                                      " in user database")

parseGroup :: [GroupEntry] -> ReadP GroupID
parseGroup db = do name <- munch1 (/= ':')
                   case resolveGroup db name of
                     Just gid -> return gid
                     Nothing  -> fail ("cannot find " ++ name ++
                                       " in group database")

parseExtLongTextFrom :: [UserEntry] -> [GroupEntry] -> ReadP ACL
parseExtLongTextFrom udb gdb = do
  _ <- string "user::"
  ow <- parseLongTextPermset
  us <- many $ do _ <- string "\nuser:"
                  uid <- readPrec_to_P readPrec 0 <++ parseUser udb
                  _ <- char ':'
                  p1 <- parseLongTextPermset
                  _ <- option p1 effective
                  return (uid,p1)
  _ <- string "\ngroup::"
  og <- parseLongTextPermset
  _ <- option og effective
  gs <- many $ do _ <- string "\ngroup:"
                  gid <- readPrec_to_P readPrec 0 <++ parseGroup gdb
                  _ <- char ':'
                  p2 <- parseLongTextPermset
                  _ <- option p2 effective
                  return (gid,p2)
  _ <- string "\nmask::"
  m <- parseLongTextPermset
  _ <- string "\nother::"
  ot <- parseLongTextPermset
  return $ ExtendedACL ow (fromListWith unionPermsets us)
                       og (fromListWith unionPermsets gs) m ot
      where effective = do skipSpaces
                           _ <- string "#effective:"
                           parseLongTextPermset

parseShortTextForm :: ReadP ACL
parseShortTextForm = parseMinShortTextForm +++ parseExtShortTextForm

parseMinShortTextForm :: ReadP ACL
parseMinShortTextForm = do
  _ <- string "u::"
  ow <- parseShortTextPermset
  _ <- string ",g::"
  og <- parseShortTextPermset
  _ <- string ",o::"
  ot <- parseShortTextPermset
  return $ MinimumACL ow og ot

parseExtShortTextForm :: ReadP ACL
parseExtShortTextForm = do
  _ <- string "u::"
  ow <- parseShortTextPermset
  us <- many $ do _ <- string ",u:"
                  uid <- readPrec_to_P readPrec 0
                  _ <- char ':'
                  p1 <- parseShortTextPermset
                  return (uid,p1)
  _ <- string ",g::"
  og <- parseShortTextPermset
  gs <- many $ do _ <- string ",g:"
                  gid <- readPrec_to_P readPrec 0
                  _ <- char ':'
                  p2 <- parseShortTextPermset
                  return (gid,p2)
  _ <- string ",m::"
  m <- parseShortTextPermset
  _ <- string ",o::"
  ot <- parseShortTextPermset
  return $ ExtendedACL ow (fromListWith unionPermsets us)
                       og (fromListWith unionPermsets gs) m ot

toAclT :: MonadBase IO m => ACL -> AclT m ()
toAclT (MinimumACL ow og ot) =
    void $ runListT $ getEntries
             [setEntry UserObj ow, setEntry GroupObj og, setEntry Other ot]
toAclT (ExtendedACL ow us og gr m ot) =
    void $ runListT $ getEntries
             ([setEntry UserObj ow] ++
              map (uncurry setEntry . first User) (toList us) ++
              [setEntry GroupObj og] ++
              map (uncurry setEntry . first Group) (toList gr) ++
              [setEntry Mask m, setEntry Other ot]
             )

addPermset :: MonadBase IO m => Permset -> PermsetT m ()
addPermset (Permset r w x) = do when r (addPerm Read)
                                when w (addPerm Write)
                                when x (addPerm Execute)

setEntry :: MonadBase IO m => Tag -> Permset -> EntryT m ()
setEntry t p = setTag t >> changePermset (addPermset p)

genericSet :: AclT IO () -> ACL -> IO ()
genericSet aclt acl =
    case acl of
      MinimumACL{}              -> runNewAclT 3 $ do toAclT acl
                                                     aclt
      ExtendedACL _ us _ gr _ _ -> runNewAclT (4 + size us + size gr) $
                                   do toAclT acl
                                      aclt

-- | Set the ACL for a file.
setACL :: FilePath -> ACL -> IO ()
setACL path = genericSet (setFileACL path Access)

-- | Set the default ACL for a directory.
setDefaultACL :: FilePath -> ACL -> IO ()
setDefaultACL path = genericSet (setFileACL path Default)

-- | Set the ACL for a file, given its file descriptor.
fdSetACL :: Fd -> ACL -> IO ()
fdSetACL fd = genericSet (setFdACL fd)

genericGetACL :: IO String -> IO ACL
genericGetACL f = do udb <- getAllUserEntries
                     gdb <- getAllGroupEntries
                     readLong udb gdb <$> f
    where readLong udb gdb str =
              case readP_to_S (parseLongTextFrom udb gdb) str of
                []  -> error "getACL: error parsing ACL long text form"
                x:_ -> fst x

-- | Retrieve the ACL from a file.
getACL :: FilePath -> IO ACL
getACL path = genericGetACL $ getFileACL path Access toText

-- | Retrieve the default ACL from a directory (return @'Nothing'@ if there is
-- no default ACL).
getDefaultACL :: FilePath -> IO (Maybe ACL)
getDefaultACL path = do udb <- getAllUserEntries
                        gdb <- getAllGroupEntries
                        readLong udb gdb <$> getFileACL path Default toText
    where readLong udb gdb str =
              case readP_to_S (parseLongTextFrom udb gdb) str of
                []  -> Nothing
                x:_ -> Just $ fst x

-- | Retrieve the ACL from a file, given its file descriptor.
fdGetACL :: Fd -> IO ACL
fdGetACL fd = genericGetACL $ getFdACL fd toText
