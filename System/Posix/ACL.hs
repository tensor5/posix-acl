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

import           Control.Monad                (foldM, replicateM_, when)
import           Data.Bits                    (Bits, (.&.))
import           Data.Map
import           System.Posix.ACL.Acl_h       (cAclExecute, cAclRead, cAclWrite)
import           System.Posix.ACL.Internals   hiding (ACL, Permset)
import qualified System.Posix.ACL.Internals   as I
import           System.Posix.Types           (Fd, GroupID, UserID)
import           Text.ParserCombinators.ReadP
import           Text.Read                    hiding ((+++), (<++))


-- | A combination of read, write and execute permissions.
data Permset = Permset { hasRead    :: Bool
                       , hasWrite   :: Bool
                       , hasExecute :: Bool
                       } deriving Eq

toPermset :: (Bits a, Integral a) => a -> Permset
toPermset a =
    Permset (hasCPerm cAclRead) (hasCPerm cAclWrite) (hasCPerm cAclExecute)
        where hasCPerm x = x .&. fromIntegral a == x

-- | No permission.
emptyPermset :: Permset
emptyPermset = Permset False False False

-- | Read, write and execute permissions.
fullPermset :: Permset
fullPermset = Permset True True True

-- | Give a permission if any of the two arguments grant that permission.
unionPermsets :: Permset -> Permset -> Permset
unionPermsets p q = Permset (hasRead p || hasRead q)
                    (hasWrite p || hasWrite q)
                    (hasExecute p || hasExecute q)

-- | Give a permission if both the arguments grant that permission.
intersectPermsets :: Permset -> Permset -> Permset
intersectPermsets p q = Permset (hasRead p && hasRead q)
                        (hasWrite p && hasWrite q)
                        (hasExecute p && hasExecute q)

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
  return (unionPermsets r (unionPermsets w x))

parseShortTextPermset :: ReadP Permset
parseShortTextPermset = do
  skipSpaces
  r <- parseRead <++ return emptyPermset
  w <- parseWrite <++ return emptyPermset
  x <- parseExecute <++ return emptyPermset
  return (unionPermsets r (unionPermsets w x))

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
                         parseLongTextFrom +++ parseShortTextForm

parseLongTextFrom :: ReadP ACL
parseLongTextFrom = parseMinLongTextFrom +++ parseExtLongTextFrom

parseMinLongTextFrom :: ReadP ACL
parseMinLongTextFrom = do
  _ <- string "user::"
  ow <- parseLongTextPermset
  _ <- string "\ngroup::"
  og <- parseLongTextPermset
  _ <- string "\nother::"
  ot <- parseLongTextPermset
  return $ MinimumACL ow og ot

parseExtLongTextFrom :: ReadP ACL
parseExtLongTextFrom = do
  _ <- string "user::"
  ow <- parseLongTextPermset
  us <- many $ do _ <- string "\nuser:"
                  uid <- readPrec_to_P readPrec 0
                  _ <- char ':'
                  p1 <- parseLongTextPermset
                  _ <- option p1 effective
                  return (uid,p1)
  _ <- string "\ngroup::"
  og <- parseLongTextPermset
  _ <- option og effective
  gs <- many $ do _ <- string "\ngroup:"
                  gid <- readPrec_to_P readPrec 0
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

pokeCPermset :: I.Permset -> Permset -> IO ()
pokeCPermset cperms perms = do
  when (hasRead perms) (addPerm cperms Read)
  when (hasWrite perms) (addPerm cperms Write)
  when (hasExecute perms) (addPerm cperms Execute)

toCACL :: ACL -> IO I.ACL
toCACL (MinimumACL ow og ot) = do cacl <- newACL 3
                                  replicateM_ 3 (createEntry cacl)
                                  ents <- getEntries cacl
                                  setUserObjEnt ow (head ents)
                                  setGroupObjEnt og (ents!!1)
                                  setOtherEnt ot (ents!!2)
                                  return cacl
toCACL (ExtendedACL ow us og gr m ot) = do
  cacl <- newACL (4 + size us + size gr)
  replicateM_ (4 + size us + size gr) (createEntry cacl)
  ents <- getEntries cacl
  setUserObjEnt ow (head ents)
  mapM_ setUserEnt (zip (userSubStr ents) (toList us))
  setGroupObjEnt og (groupElem ents)
  mapM_ setGroupEnt (zip (groupSubStr ents) (toList gr))
  setTagType (maskElem ents) Mask
  m_p <- getPermset (maskElem ents)
  pokeCPermset m_p m
  setOtherEnt ot (otherElem ents)
  return cacl
      where userSubStr xs = take (size us) $ drop 1 xs
            groupElem xs = xs!!(1 + size us)
            groupSubStr xs = take (size gr) $ drop (2 + size us) xs
            maskElem xs = xs!!(2 + size us + size gr)
            otherElem xs = xs!!(3 + size us + size gr)
            setUserEnt (e,(u,p)) = do setTagType e User
                                      setQualifier e (UserID u)
                                      s <- getPermset e
                                      pokeCPermset s p
            setGroupEnt (e,(g,p)) = do setTagType e Group
                                       setQualifier e (GroupID g)
                                       s <- getPermset e
                                       pokeCPermset s p

setUserObjEnt :: Permset -> Entry -> IO ()
setUserObjEnt p e = do setTagType e UserObj
                       s <- getPermset e
                       pokeCPermset s p

setGroupObjEnt :: Permset -> Entry -> IO ()
setGroupObjEnt p e = do setTagType e GroupObj
                        s <- getPermset e
                        pokeCPermset s p

setOtherEnt :: Permset -> Entry -> IO ()
setOtherEnt p e = do setTagType e Other
                     s <- getPermset e
                     pokeCPermset s p

-- | Set the ACL for a file.
setACL :: FilePath -> ACL -> IO ()
setACL path acl = toCACL acl >>= setFileACL path Access

-- | Set the default ACL for a directory.
setDefaultACL :: FilePath -> ACL -> IO ()
setDefaultACL path acl = toCACL acl >>= setFileACL path Default

-- | Set the ACL for a file, given its file descriptor.
fdSetACL :: Fd -> ACL -> IO ()
fdSetACL fd acl = toCACL acl >>= setFdACL fd

-- | Retrieve the ACL from a file.
getACL :: FilePath -> IO ACL
getACL path = getFileACL path Access >>= peekCACL

-- | Retrieve the default ACL from a directory.
getDefaultACL :: FilePath -> IO ACL
getDefaultACL path = getFileACL path Default >>= peekCACL

-- | Retrieve the ACL from a file, given its file descriptor.
fdGetACL :: Fd -> IO ACL
fdGetACL fd = getFdACL fd >>= peekCACL

peekCACL :: I.ACL -> IO ACL
peekCACL cacl = do
  ents <- getEntries cacl
  foldM addCEntry (MinimumACL emptyPermset emptyPermset emptyPermset) ents


addCEntry :: ACL -> I.Entry -> IO ACL
addCEntry acl ent = do
  tag <- getTagType ent
  perms <- getPermset ent
  n <- permsetToIntegral perms
  addPermsetWithTag tag ent acl (toPermset (n::Int))
    where addPermsetWithTag t e a p =
              case t of
                User -> do Just (UserID uid) <- getQualifier e
                           return $ addUserPermset uid p a
                Group -> do Just (GroupID gid) <- getQualifier e
                            return $ addGroupPermset gid p a
                UserObj -> return $ addUserObjPermset p a
                GroupObj -> return $ addGroupObjPermset p a
                Other -> return $ addOtherPermset p a
                Mask -> return $ setMaskPermset p a
                Undefined -> return undefined




addUserPermset :: UserID -> Permset -> ACL -> ACL
addUserPermset uid p (MinimumACL ow og ot) =
    ExtendedACL ow (singleton uid p) og empty emptyPermset ot
addUserPermset uid p acl =
    acl { usersPerms = insertWith unionPermsets uid p (usersPerms acl) }

addGroupPermset :: GroupID -> Permset -> ACL -> ACL
addGroupPermset gid p (MinimumACL ow og ot) =
    ExtendedACL ow empty og (singleton gid p) emptyPermset ot
addGroupPermset gid p acl =
    acl { groupsPerms = insertWith unionPermsets gid p (groupsPerms acl) }

addUserObjPermset :: Permset -> ACL -> ACL
addUserObjPermset p acl = acl { ownerPerms = unionPermsets p (ownerPerms acl) }

addGroupObjPermset :: Permset -> ACL -> ACL
addGroupObjPermset p acl =
    acl { owningGroupPerms = unionPermsets p (owningGroupPerms acl) }

setMaskPermset :: Permset -> ACL -> ACL
setMaskPermset p (MinimumACL ow og ot) = ExtendedACL ow empty og empty p ot
setMaskPermset p acl = acl { mask = unionPermsets p (mask acl) }

addOtherPermset :: Permset -> ACL -> ACL
addOtherPermset p acl = acl { otherPerms = unionPermsets p (otherPerms acl) }
