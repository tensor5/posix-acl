{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE Safe                  #-}

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
-- Support for POSIX.1e /Access Control Lists/ (ACL), defined in section 23 of
-- the draft standard <http://users.suse.com/~agruen/acl/posix/Posix_1003.1e-990310.pdf IEEE Std 1003.1e>.
--
--------------------------------------------------------------------------------

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

import           Control.Applicative          (empty, (<$>), (<*>), (<|>))
import           Control.Arrow                (first)
import           Control.Monad                (void, when)
import           Control.Monad.Base           (MonadBase)
import           Control.Monad.Trans.List     (ListT (..))
import           Data.Function                (on)
import           Data.List                    (find, nubBy, partition)
import           Data.Map                     hiding (empty, foldl, map, null,
                                               partition)
import           Data.Maybe                   (catMaybes)
import           System.Posix.ACL.Internals
import           System.Posix.Types           (Fd, GroupID, UserID)
import           System.Posix.User
import           Text.ParserCombinators.ReadP
import           Text.Read                    hiding (get, look, (<++))


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
  r <- parseRead <|> parseDash
  w <- parseWrite <|> parseDash
  x <- parseExecute <|> parseDash
  return (r `unionPermsets` w `unionPermsets` x)

parseShortTextPermset :: ReadP Permset
parseShortTextPermset = do
  r <- parseRead <++ return emptyPermset
  w <- parseWrite <++ return emptyPermset
  x <- parseExecute <++ return emptyPermset
  return (r `unionPermsets` w `unionPermsets` x)

parsePermset :: ReadP Permset
parsePermset = skipSpaces >> parseLongTextPermset <|> parseShortTextPermset

instance Read Permset where
    readPrec = lift parsePermset


data Entry = Entry
    { entryTag     :: Tag
    , entryPermset :: Permset
    } deriving (Eq, Read, Show)

data TextForm = Long
              | Short
                deriving Eq

parseEntry :: TextForm -> [UserEntry] -> [GroupEntry] -> ReadP Entry
parseEntry tf udb gdb =
    parseSingleEntry tf 'u' "ser" (Right UserObj) <|>
    parseSingleEntry tf 'u' "ser"
      (Left $ User <$> parseUser udb <++ readPrec_to_P readPrec 0) <|>
    parseSingleEntry tf 'g' "roup" (Right GroupObj) <|>
    parseSingleEntry tf 'g' "roup"
      (Left $ Group <$> parseGroup gdb <++ readPrec_to_P readPrec 0) <|>
    parseSingleEntry tf 'm' "ask" (Right Mask) <|>
    parseSingleEntry tf 'o' "ther" (Right Other)


skipWhites :: ReadP ()
skipWhites = do str <- look
                skip str
    where skip ('\t' : str) = get >> skip str
          skip (' '  : str) = get >> skip str
          skip _            = return ()

parseSingleEntry :: TextForm -> Char -> String -> Either (ReadP Tag) Tag
                 -> ReadP Entry
parseSingleEntry tf x xs eit =
    case tf of
      Long  -> do void $ string (x:xs)
                  Entry <$> secondField <*> parseLongTextPermset
      Short -> do void $ char x
                  optional (string xs)
                  Entry <$> secondField <*> parseShortTextPermset
    where secondField = do skipWhites
                           void $ char ':'
                           t <- case eit of
                                  Left qual -> skipWhites >> qual
                                  Right tag -> return tag
                           skipWhites
                           void $ char ':'
                           skipWhites
                           return t

comment :: ReadP String
comment = char '#' >> munch (/= '\n')

parseLongTextEntries :: [UserEntry] -> [GroupEntry] -> ReadP [Entry]
parseLongTextEntries udb gdb = do ls <- many line
                                  skipSpaces
                                  return $ catMaybes ls
    where line = do skipSpaces
                    (comment >> return Nothing) <|> (do e <- parseEntry
                                                             Long udb gdb
                                                        skipWhites
                                                        optional comment
                                                        eol
                                                        return $ Just e)
          eol = do str <- look
                   case str of
                     ""     -> return ()
                     '\n':_ -> return ()
                     _      -> empty

parseShortTextEntries :: [UserEntry] -> [GroupEntry] -> ReadP [Entry]
parseShortTextEntries udb gdb =
    parseEntry Short udb gdb `sepBy1` (skipWhites >> char ',' >> skipWhites)


-- | Represent a valid ACL as defined in POSIX.1e. The @'Show'@ instance is
-- defined to output the /Long Text Form/ of the ACL (see section 23.3.1 of
-- <http://users.suse.com/~agruen/acl/posix/Posix_1003.1e-990310.pdf IEEE Std 1003.1e>),
-- while the @'Read'@ instance is defined to be able to parse both the long and
-- short text form (@'read'@ only parses valid ACLs).
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

validACL :: [Entry] -> Maybe ACL
validACL es =
    let (uos,es1) = partition isUserObj es
        (us, es2) = partition isUser es1
        (gos,es3) = partition isGroupObj es2
        (gs, es4) = partition isGroup es3
        (ms, es5) = partition isMask es4
        (os, [] ) = partition isOther es5
    in case (uos,us,gos,gs,ms,os) of
         ([u],[],[g],[],[] ,[o]) -> Just $ MinimumACL (entryPermset u)
                                                      (entryPermset g)
                                                      (entryPermset o)
         ([u],_ ,[g],_ ,[m],[o]) ->
             case (toMap tagUserID us, toMap tagGroupID gs) of
               (Just mu, Just mg) -> Just $ ExtendedACL (entryPermset u)
                                                        mu
                                                        (entryPermset g)
                                                        mg
                                                        (entryPermset m)
                                                        (entryPermset o)
               _                  -> Nothing
         _                       -> Nothing
    where isUserObj (Entry UserObj _) = True
          isUserObj _                 = False
          isUser (Entry (User _) _) = True
          isUser _                  = False
          isGroupObj (Entry GroupObj _) = True
          isGroupObj _                  = False
          isGroup (Entry (Group _) _) = True
          isGroup _                   = False
          isMask (Entry Mask _) = True
          isMask _              = False
          isOther (Entry Other _) = True
          isOther _               = False
          toMap f xs =
              if nubBy ((==) `on` (f . entryTag)) xs == xs
              then Just $ fromList $
                   map (\e -> (f $ entryTag e, entryPermset e)) xs
              else Nothing

instance Show ACL where
    showsPrec = showsLongText

-- | Convert an ACL to its /Long Text Form/ (see section 23.3.1 of
-- <http://users.suse.com/~agruen/acl/posix/Posix_1003.1e-990310.pdf IEEE Std 1003.1e>).
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
-- <http://users.suse.com/~agruen/acl/posix/Posix_1003.1e-990310.pdf IEEE Std 1003.1e>).
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
    readPrec =
        lift $ parseValidLongTextACL [] [] <|> parseValidShortTextACL [] []

parseValidLongTextACL :: [UserEntry] -> [GroupEntry] -> ReadP ACL
parseValidLongTextACL udb gdb =
    parseLongTextEntries udb gdb >>= maybe empty return . validACL

parseValidShortTextACL :: [UserEntry] -> [GroupEntry] -> ReadP ACL
parseValidShortTextACL udb gdb =
    skipSpaces >>
    parseShortTextEntries udb gdb >>= maybe empty return . validACL


resolveUser :: [UserEntry] -> String -> Maybe UserID
resolveUser db name = userID <$> find ((== name) . userName) db

resolveGroup :: [GroupEntry] -> String -> Maybe GroupID
resolveGroup db name = groupID <$> find ((== name) . groupName) db

parseUser :: [UserEntry] -> ReadP UserID
parseUser db = do name <- munch1 (`notElem` "\t :")
                  case resolveUser db name of
                    Just uid -> return uid
                    Nothing  -> fail ("cannot find " ++ name ++
                                      " in user database")

parseGroup :: [GroupEntry] -> ReadP GroupID
parseGroup db = do name <- munch1 (`notElem` "\t :")
                   case resolveGroup db name of
                     Just gid -> return gid
                     Nothing  -> fail ("cannot find " ++ name ++
                                       " in group database")

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

readLong :: [UserEntry] -> [GroupEntry] -> String -> ACL
readLong udb gdb str =
    case [ x | (x, "") <- readP_to_S (parseValidLongTextACL udb gdb) str ] of
      [x] -> x
      []  -> error "getACL: ambiguous parse of ACL long text form"
      _   -> error "getACL: no parse of ACL long text form"

-- | Retrieve the ACL from a file.
getACL :: FilePath -> IO ACL
getACL path = genericGetACL $ getFileACL path Access toText

-- | Retrieve the default ACL from a directory (return @'Nothing'@ if there is
-- no default ACL).
getDefaultACL :: FilePath -> IO (Maybe ACL)
getDefaultACL path = do udb <- getAllUserEntries
                        gdb <- getAllGroupEntries
                        readLong' udb gdb <$> getFileACL path Default toText
    where readLong' _   _   ""  = Nothing
          readLong' udb gdb str = Just $ readLong udb gdb str

-- | Retrieve the ACL from a file, given its file descriptor.
fdGetACL :: Fd -> IO ACL
fdGetACL fd = genericGetACL $ getFdACL fd toText
