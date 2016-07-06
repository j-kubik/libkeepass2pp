/*Copyright (C) 2016 Jaroslaw Kubik
 *
   This file is part of libkeepass2pp library.

libkeepass2pp is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published bythe Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

libkeepass2pp is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with libkeepass2pp.  If not, see <http://www.gnu.org/licenses/>.
*/
#ifndef KDBXDATABASE_H
#define KDBXDATABASE_H

#include <vector>
#include <list>
#include <string>
#include <array>
#include <map>
#include <memory>
#include <ctime>
#include <bitset>
#include <cstring>
#include <future>
#include <type_traits>
#include <set>
#include <istream>

#include "util.h"
#include "icon.h"
#include "pipeline.h"
#include "cryptorandom.h"

namespace Kdbx{

namespace Internal{
template <typename T>
class Parser;
}

/**
 * @brief The MemoryProtection enum is used to indicate which of string fields
 *        should use In-Memory protection.
 */
enum class MemoryProtection: std::size_t{
    Title,
    UserName,
    Password,
    Url,
    Notes,
    AutoHide, //?
    Max /// count of memery protection enumerations.
};

/**
 * @brief MemoryProtectionFlags is a type representing set fo MemoryProtection flags.
 */
typedef EnumFlags<MemoryProtection, MemoryProtection::Max> MemoryProtectionFlags;

/**
 * @brief The Times structure represents usual set of timestamps and additional
 *        information found in groups and entries of Kdbx database.
 */
struct Times{
public:
    std::time_t creation; //! Entry/group creation timestamp;
    std::time_t lastModification; //! Entry/group last modification timestamp;
    std::time_t lastAccess; //! Entry/group last access timestamp;
    std::time_t expiry; //! Entry/group expiry date timestamp;
    bool expires;       //! Set to true if entry/group should ever expire.
    uint64_t usageCount; //! Usage count of entry/group. It is unknown what operations are considered to be usage by original KeePass. libkeepass2 makes no use of this variable other than just preserving its value acriss save/load operations.
    std::time_t locationChanged; //! Entry/group timestamp marking lase time when parent gorup was changed.

    /**
     * @brief Constructor that does not initialize any fileds of Times structure.
     *
     * This constructor is useful if fields are to be assigned after construction
     * anyway.
     */
    inline Times(DoNotInitEnum) noexcept
    {}

    /**
     * @brief Constructor that initializes each field of Times structure to zero.
     */
    inline Times() noexcept
        :creation(0),
          lastModification(0),
          lastAccess(0),
          expiry(0),
          expires(false),
          usageCount(0),
          locationChanged(0)
    {}

    /**
     * @brief Creates a current Times structure.
     * Iy has all fields set to 0, except for \p creation, \p lastModification and
     * \p lastAccess that are set to current time (as reported by \p time() function).
     */
    static Times nowTimes() noexcept{
        Times result;
        result.creation = time(nullptr);
        result.lastModification = result.creation;
        result.lastAccess = result.creation;
        return result;
    }
};

class CompositeKey;

class DatabaseModel;
template <typename ModelType>
class DatabaseModelCTRP;

/**
 * @brief The Database class represents KeePass 2 database.
 *
 * Database consists of a root group and Settings object that
 * contains global database settings.
 *
 * The root group owned by database owns (directly or indirectly)
 * all groups and databse entries owned by the database.
 */

class Database{
public:

    /**
     * @brief Ptr is an unique owning pointer to a Database object.
     *
     * It releases pointed database when it goes out of scope.
     */
    typedef std::unique_ptr<Database> Ptr;

    class Settings;
    class Version;
    class Entry;
    class Group;
    class Meta;

    /** @brief File class represents a partialy open KDBX file.
     *
     * It is used to stroe basic configuration parameters that are read from KDBX file
     * and are necesary in order to decrypt it. Those paramaters are split into
     * Settings and random parameters. Settings are user-accessible parameters
     * describing how database is to be serialized. Random paramaters are buffers
     * of random bytes used in cryptographic process. Those buffers are not preserved
     * between deserialization and serialization of database. Each time database is
     * serialized, cryptografic RNG is used to generate new contents of those buffers.
     */
    class File{
    public:
        /** @brief Compression algorithm to use.
         *
         * KDBX format currently supports only gzip compression or no compression.
         */
        enum class CompressionAlgorithm: uint32_t
        {
            /// No compression.
            None = 0,

            /// GZip compression.
            GZip = 1,

            Count = 2
        };

        static const std::array<uint8_t, 16> AES_CBC_256_UUID;

        /** @brief Settings is a structure that groups together user accesible Settings
         *         that are used when serializing and deserializing a database.
         */
        struct Settings{
            /** @brief Unique, owning pointer to a Settings object.*/
            typedef std::unique_ptr<Settings> Ptr;

            bool encrypt; //! Whether database is to be encrypted.
                          //! This filed only indicates if all expected fields
                          //! were found in the header. If false, \p cipherId field
                          //! and all fields concerning compression are to be ignored.
            bool compress; //! Whether database is to be compressed.
                           //! This filed only indicates if CompressionAlgorithm field
                           //! was found in the header. If false, \p compression field
                           //! is to be ignored.
            std::array<uint8_t, 16> cipherId; //! Compression sheme to use.
                                              //! Currently KDBX format only supports
                                              //! AES 256 CBC encryption.
            uint64_t transformRounds; //! Password transformation rounds to be applied.
            RandomStream::Algorithm crsAlgorithm; //! Random stream algorithm to be
                                                      //! used. This random stream is
                                                      //! used for additional
                                                      //! protection of sensitive data
                                                      //! inside the stream.
            CompressionAlgorithm compression; //! Compression algorithm to be used.

            /** @brief Constructs default Settings structure. Default values are:
             *  - encrypt and compress are set to true;
             *  - transformRounds is set to 5000;
             *  - crsAlgorithm is set to RandomStream::Algorithm::Salsa20;
             *  - compression is set to CompressionAlgorithm::GZip;
             *  - cipherId is set to AES_CBC_256_UUID.
             */
            inline Settings() noexcept
                :encrypt(true),
                  compress(true),
                  cipherId(AES_CBC_256_UUID),
                  transformRounds(5000),
                  crsAlgorithm(RandomStream::Algorithm::Salsa20),
                  compression(CompressionAlgorithm::GZip)
            {}

        };

    private:
        std::unique_ptr<std::istream> ffile;

        std::array<uint8_t, 32> masterSeed;
        std::array<uint8_t, 32> transformSeed;
        std::array<uint8_t, 16> encryptionIV;
        std::array<uint8_t, 32> streamStartBytes;

        SafeVector<uint8_t> protectedStreamKey;

        /**
         * @brief settings Settings object used during deserialization.
         *
         * This field can be accessed even in invalid \p File objects.
         */
        Settings settings;

    public:
        /** @brief Returns \p true if a proper composite key is required in order to
         *         properly deserialize a database.
         */
        bool needsKey();

        /** @brief Checks whether \p File object is valid.
         *
         * getDatabase() can only be called on a valid object.
         *
         * @note \p settings member of \p File class can be acceses even if \p File
         *       object is invalid.
         */
        inline bool valid() const noexcept{
            return ffile.get();
        }

        /** @brief Initializes deserialization process.
         * @param key CompositeKey that is used in order to decrypt datbase.
         *        The key might not be necesary (in which case this parameter is
         *        ignored); use needsKey() in order to determine wheter a key is
         *        required.
         * @return std::future object that gets an owning pointer to database
         *         as its value.
         *
         * This method starts deserialization process asynchronously. Returned
         * std::future can be used to determine wheter a deserialized database is
         * ready. If deserialization was interrupted by an error, returned future
         * object will throw an apropriate exception in \p get() method.
         *
         * This method call renders \p File object invalid. Any subsequent calls
         * to getDatabase() will produce undefined behavior. You can check if \p
         * File object is valid using valid() method.
         * @note \p settings member of \p File class can be acceses even if \p File
         *       object is invalid.
         */
        std::future<Database::Ptr> getDatabase(const CompositeKey& key);

        /** @brief Initializes deserialization process.
         * @return std::future object that gets an owning pointer to database
         *         as its value.
         *
         * This method starts deserialization process asynchronously. Returned
         * std::future can be used to determine wheter a deserialized database is
         * ready. If deserialization was interrupted by an error, returned future
         * object will throw an apropriate exception in \p get() method.
         *
         * This is overload that doesn't use composite key, and can only be used
         * if database is not encrypted. You can check whether composite key is
         * necesary using needsKey() method. If this method is called while
         * needsKey() returns \p true, an std::runtime_error is thrown with
         * apropriate error message.
         *
         * This method call renders \p File object invalid. Any subsequent calls
         * to getDatabase() will produce undefined behavior. You can check if \p
         * File object is valid using valid() method.
         * @note \p settings member of \p File class can be acceses even if \p File
         *       object is invalid.
         */
        std::future<Database::Ptr> getDatabase();


        friend class Database;
    };

    /** @brief Global database settings.
     *
     * This class is storing database global settings.
     *
     */
    class Settings{
    public:
        /** @brief Unique, owning pointer to a Settings object.*/
        typedef std::unique_ptr<Settings> Ptr;

        //ToDo: rethink default values here.
        /** @brief Initializes settings to default values.
         * @param settings File settings object used to copy-initalize fileSettings
         *        field.
         *
         * Default values are:
         *  - databaseName, databaseDescription, defaultUsername and color are set
         *    to empty strings.
         *  - databaseNameChanged, databaseDescriptionChanged, defaultUsernameChanged,
         *    masterKeyChanged, recycleBinChanged and entryTemplatesGroupChanged are
         *    set to 0;
         *  - maintenanceHistoryDays is set to 365;
         *  - historyMaxItems, masterKeyChangeRec, masterKeyChangeForce and
         *    historyMaxSize are set to -1;
         *  - memoryProtection is set to MemoryProtection::Password;
         *  - recycleBinUUID, entryTemplatesGroup, lastSelectedGroup and
         *    lastTopVisibleGroup is set no null UUID.
         *  - recycleBinEnabled is set to false.
         */
        inline Settings(const Database::File::Settings& settings = Database::File::Settings())
            :fileSettings(settings),
              masterKeyChanged(0),
              maintenanceHistoryDays(365),
              historyMaxItems(-1),
              masterKeyChangeRec(-1),
              masterKeyChangeForce(-1),
              historyMaxSize(-1),
              memoryProtection(1 << std::size_t(MemoryProtection::Password)),
              recycleBinEnabled(false),
              fnameChanged(0),
              fdescriptionChanged(0),
              fdefaultUsernameChanged(0)
        {}

//        Settings(Settings&&) = default;
//        Settings& operator=(Settings&&) = default;
//        Settings(const Settings&) = default;

        File::Settings fileSettings;
        std::string color; // just a raw string for now...
        std::time_t masterKeyChanged;
        unsigned int maintenanceHistoryDays;
        int historyMaxItems;
        int64_t masterKeyChangeRec;
        int64_t masterKeyChangeForce;
        int64_t historyMaxSize;
        MemoryProtectionFlags memoryProtection;
        Uuid lastSelectedGroup;
        Uuid lastTopVisibleGroup;
        bool recycleBinEnabled;

        inline const std::string& name() const noexcept{
            return fname;
        }

        void setName(std::string name) noexcept;

        const std::time_t& nameChanged() const noexcept{
            return fdescriptionChanged;
        }

        inline const std::string& description() const noexcept{
            return fdescription;
        }

        void setDescription(std::string description) noexcept;

        const std::time_t& descriptionChanged() const noexcept{
            return fdescriptionChanged;
        }

        inline const std::string& defaultUsername() const noexcept{
            return fdefaultUsername;
        }

        void setDefaultUsername(std::string username) noexcept;

        const std::time_t& defaultUsernameChanged() const noexcept{
            return fdefaultUsernameChanged;
        }

    private:
        std::string fname;
        std::string fdescription;
        std::string fdefaultUsername;

        std::time_t fnameChanged;
        std::time_t fdescriptionChanged;
        std::time_t fdefaultUsernameChanged;


        friend class Internal::Parser<Database::Meta>;
        friend class Internal::Parser<Database>;
        friend class Database;
    };

    /** @brief The Version class represents a version of a database entry.
     *
     * A version can be owned by at most one entry at a time.
     */
    class Version{
    public:
        /**
         * @brief Ptr is an unique owning pointer to a Version object.
         *
         * It releases pointed object when it goes out of scope.
         */
        typedef std::unique_ptr<Version> Ptr;

        class Binary;

        /**
         * @brief Creates default version object that doesn't belong to any
         * database.
         *
         * All public fields of created version object are default-initialized,
         * except icon, that is set to Kdbx::StandardIcon::Key standard icon, and
         * times that are set to Times::nowTimes().
         */
        inline Version() noexcept
            :icon(StandardIcon::Key),
              times(Times::nowTimes()),
              fparent(nullptr)
        {}

        /**
         * @brief Copy constructor for a Version object.
         *
         * Constructed object contains copies of all public variables of object \p
         * v, but it doesn't belong to any entry.
         *
         * @note Version that doesn't belong to any entry cannot belong to a group
         *       or a database.
         */
        inline Version(const Version& v)
            :icon(v.icon),
              fgColor(v.fgColor),
              bgColor(v.bgColor),
              overrideUrl(v.overrideUrl),
              tags(v.tags),
              times(v.times),
              strings(v.strings),
              binaries(v.binaries),
              autoType(v.autoType),
              fparent(nullptr)

        {}

        /**
         * @brief Returns an entry object that a Version object belongs to.
         *
         * If a Version object doesn't belong to any Entry object, it returns
         * nullptr.
         */
        inline const Entry* parent() const noexcept{
            return fparent;
        }

        /**
         * @brief Returns an entry object that a Version object belongs to.
         *
         * If a Version object doesn't belong to any Entry object, it returns
         * nullptr.
         */
        inline Entry* parent() noexcept{
            return fparent;
        }

        /**
         * @brief Checks wheter an entry is an ancestor of current version.
         * @param entry Pointer to an \p Entry object that might be an ancestor
         * of a version.
         *        This pointer cannot be nullptr.
         *
         * Entry is ancestor of a version if owns that version object.
         *
         * @return \p true if \p entry is ancestor to a version;
         * \p false otherwise.
         */
        inline bool ancestor(const Entry* entry) const noexcept{
            return parent() == entry;
        }

        /**
         * @brief Checks wheter an entry is an ancestor of current version.
         * @param entry Pointer to an \p Entry object that might be an ancestor
         * of a version.
         *        This pointer cannot be nullptr.
         *
         * Entry is ancestor of a version if owns that version object.
         *
         * @return \p true if \p entry is ancestor to a version;
         * \p false otherwise.
         */
        inline bool ancestor(const Group* group) const noexcept{
            if (parent())
                return parent()->ancestor(group);
        }

        /**
         * @brief Returns index of a version in it's parent entry.
         *
         * If version has no parent entry, result is undefined behavior.
         *
         * @return Index of a version in it's parent entry.
         */
        size_t index() const noexcept;

        /**
         * @brief Removes a version from it's parent entry.
         *
         * If version has no parent entry or is the only version object
         * that its parent entry owns, result is undefined behavior.
         *
         * It destroys version object.
         */
        void remove() noexcept{
            parent()->removeVersion(this);
        }

        /**
         * @brief Removes a version from it's parent entry.
         *
         * If version has no parent entry or is the only version object
         * that its parent entry owns, result is undefined behavior.
         *
         * It removes version object from it's parent entry and returns
         * ownership of it to the caller.
         */
        Ptr take() noexcept{
            return parent()->takeVersion(this);
        }

        /**
         * @brief The AutoType class contains options concerning auto-typing data
         *        directly into target program window.
         *
         * Currently libkeepass2 odder no support for any of this data other than
         * preserving it across desrializatization and serialization.
         *
         * As services like auto-typing are always strongly platform-dependent,
         * it is unclear wheter windows-based configuration can be of any use on
         * other platforms.
         */
        class AutoType{
        public:
            class Association{
            public:
                std::string window;
                std::string sequence;
            };
            enum class ObfuscationOptions{
                None = 0,
                UseClipboard = 1
            };

            std::string defaultSequence;
            std::vector<Association> items;
            ObfuscationOptions obfuscationOptions;
            bool enabled;
        };

        Icon icon;
        std::string fgColor;
        std::string bgColor;
        std::string overrideUrl;
        std::vector<std::string> tags;
        Times times;
        std::map<std::string, XorredBuffer> strings;
        // ToDo: XorredBuffer, SafeVector, or even something else?
        std::map<std::string, std::shared_ptr<SafeVector<uint8_t>>> binaries;
        AutoType autoType;

        static const char* const titleString; /// Name of title field in strings array
        static const char* const userNameString; /// Name of username field in strings array
        static const char* const passwordString; /// Name of password field in strings array
        static const char* const urlString; /// Name of URL field in strings array
        static const char* const notesString; /// Name of notes field in strings array

    private:
        /** @brief Version constructor used only internally when deserializing
         * a database.
         * @param parent Parent entry of constructed version object.
         *        This pointer cannot be nullptr.
         */
        inline Version(Entry* parent) noexcept
            :fparent(parent)
        {}

        /** @brief Adds a version into a database.
         * @param database Database that takes ownership of this version object.
         *        This pointer cannot be nullptr;
         * @param args Additional parameters. For now, it can only be empty, or
         *        a pointer to a DatabaseModel object that manges the database.
         *
         * Internal function called when inserting version, entry or group into
         * a database.
         * It ensures that database model object gets notified of any metadata
         * updates this operation my cause.
         */
        template<typename ...Args>
        void setDatabase(Database* database, Args ...args);

        Entry* fparent;

        friend class Entry;
        friend class Database;
        friend class Internal::Parser<Version>;
        friend class DatabaseModel;

    };

    /**
     * @brief The Entry class represents a database entry.
     *
     * It can be owned by at most one group at a time, and it must own at least
     * one Version object. Every entry holds internal list of pointers to owned
     * Version objects.
     *
     * Version object at the last position in an entry  is considered latest.
     * @note ToDo: sorting versions by update times, rather than insert-index?
     */
    class Entry{
    public:

        /**
         * @brief Ptr is an unique owning pointer to a Version object.
         *
         * It releases pointed object when it goes out of scope.
         */
        typedef std::unique_ptr<Entry> Ptr;


        /**
         * @brief Constructs a new Entry object that takes ownership of a
         * \p version object.
         * @param current An owning ponter to an entry version.
         *        This pointer cannot be nullptr.
         *
         * Newly created Entry has new-generated UUID. It doesn't belong to
         * any group, and it owns only \p current version object.
         */
        inline Entry(Version::Ptr current)
            :fuuid(Uuid::generate()),
              fparent(nullptr)
        {
            current->fparent = this;
            fversions.push_back(std::move(current));
        }

        /**
         * @brief Constructs a new Entry object that takes ownership of a
         * \p version object.
         * @param uuid UUID for a created Entry.
         * @param current An owning ponter to an entry version.
         *        This pointer cannot be nullptr.
         *
         * It doesn't belong to any group, and it owns only \p current
         * version object.
         */
        inline Entry(Uuid uuid, Version::Ptr current)
            :fuuid(std::move(uuid)),
              fparent(nullptr)
        {
            current->fparent = this;
            fversions.push_back(std::move(current));
        }

        /** @brief Copy-constructs a new Entry object.
         * @param entry Entry object to be copied.
         *
         * It constructs a new Entry Object, aassigns it a new-generated UUID,
         * and copies entire set of \p Version objects owned by source \p entry
         * object. Those copeis are owned by constructed Entry object; they
         * follow in the same order as original Version objects
         */
        Entry(const Entry& entry);

        /** @brief Returns a pointer to a group object that owns this entry.
         *
         * It returns \p nullptr if entry is not owned by any group.
         */
        inline Group* parent() noexcept {
            return fparent;
        }

        /** @brief Returns a pointer to a group object that owns this entry.
         *
         * It returns \p nullptr if entry is not owned by any group.
         */
        inline const Group* parent() const noexcept{
            return fparent;
        }

        /**
         * @brief Checks wheter a group is an ancestor of an entry.
         * @param group Group that might be an ancestor of an entry.
         *
         * Group is ancestor to an entry object if it owns that entry or it owns
         * that entry's ancestor group.
         *
         * @return \p true if \p group is an ancestor of an entry object; \p false otherwise.
         */
        inline bool ancestor(const Group* group) const noexcept{
            const Group* g = parent();
            while (g){
                if (g == group)
                    return true;
                g = g->parent();
            }
            return false;
        }

        /**
         * @brief Returns index of an entry in it's parent group.
         *
         * If entry has no parent group, result is undefined behavior.
         *
         * @return Index of an entry in it's parent group.
         */
        size_t index() const noexcept{
            const Group* p = parent();
            assert(p);
            for (size_t i=0; i<p->entries(); ++i){
                if (p->entry(i) == this)
                    return i;
            }
            assert("Internal error." == nullptr);
            return 0;
        }

        /**
         * @brief Removes an entry from it's parent group.
         *
         * If entry has no parent group, result is undefined behavior.
         *
         * It destroys entry object.
         */
        void remove() noexcept{
            parent()->removeEntry(this);
        }

        /**
         * @brief Removes an entry from it's parent group.
         *
         * If entry has no parent group, result is undefined behavior.
         *
         * It removes entry object from it's parent group and returns
         * ownership of it to the caller.
         */
        Ptr take() noexcept{
            return parent()->takeEntry(this);
        }

        /**
         * @brief Returns number of owned verion objects.
         */
        inline size_t versions() const noexcept{
            return fversions.size();
        }

        /**
         * @brief Returns index of a version in current entry.
         * @param version Version oned by current entry.
         *
         * If \p v is not owned by current entry, result is undefined behavior.
         *
         * @return Index of \p v in current entry.
         */
        size_t index(const Version* v) const noexcept{
            for (size_t i=0; i<versions(); ++i){
                if (version(i) == v)
                    return i;
            }
            assert("Version not in current entry." == nullptr);
            return 0;
        }

        /**
         * @brief Returns a pointer to a version object owned by an entry.
         * @param index Index of a version object to retrieve. Valid indexes are in [0, versions()).
         * @return This method never returns nullptr.
         *
         * If specified index is outside valid range, it results in undefined behavior.
         */
        inline const Version* version(size_t index) const noexcept{
            return fversions.at(index).get();
        }

        /**
         * @brief Returns a pointer to a version object owned by an entry.
         * @param index Index of a version object to retrieve. Valid indexes are in [0, versions()).
         * @return This method never returns nullptr.
         *
         * If specified index is outside valid range, it results in undefined behavior.
         */
        inline Version* version(size_t index) noexcept{
            return fversions.at(index).get();
        }

        /**
         * @brief Returns pointer to last version object owned by an entry.
         * @return This method never returns nullptr.
         *
         * It is equivalent to version(versions()-1);
         */
        inline const Version* latest() const noexcept{
            return fversions.back().get();
        }

        /**
         * @brief Returns pointer to last version object owned by an entry.
         * @return This method never returns nullptr.
         *
         * It is equivalent to version(versions()-1);
         */
        inline Version* latest() noexcept{
            return fversions.back().get();
        }

        /**
         * @brief Adds a version to an entry object.
         * @param version An owning pointer to a version object. This parameter
         *        cannot be \p nullptr.
         * @param index Represents a position at which new version is inserted
         *        into entries internal version list. Valid indexes are in
         *        [0, versions()].
         *
         * Entry takes ownership of the provided version object and inserts it
         * into internal list of version at position \p index.
         */
        void addVersion(Version::Ptr version, size_t index);

        /**
         * @brief Removes a version at postion \p index from an entry.
         * @param index index of a version object to be taken.
         *
         * It returns an ownership of removed version object to the caller.
         * Removing last version object from an entry produces unknown behavior.
         */
        Version::Ptr takeVersion(size_t index) noexcept;

        /**
         * @brief Removes a version from an entry.
         * @param version Version object to be taken. It must be owned by an
         *        entry is taken from.
         *
         * It returns an ownership of removed version object to the caller.
         * If \p version is not owned by an entry on which this method was
         * called, result is undefined behavior. Removing last version object
         * from an entry produces unknown behavior.
         */
        inline Version::Ptr takeVersion(const Version* version) noexcept{
            assert(fversions.size() > 1);
            return takeVersion(index(version));
        }

        /**
         * @brief Removes a version at postion \p index from an entry.
         * @param index index of a version object to be removed
         *
         * It deletes removed verion object.
         * Removing last version object from an entry produces unknown behavior.
         */
        inline void removeVersion(size_t index) noexcept{
            assert(fversions.size() > 1);
            fversions.erase(fversions.begin() + index);
        }

        /**
         * @brief Removes a version from an entry.
         * @param version Version object to be removed. It must be owned by an
         *        entry is taken from.
         *
         * It deletes removed verion object.
         * Removing last version object from an entry produces unknown behavior.
         * If \p version is not owned by an entry on which this method was
         * called, result is undefined behavior.
         */
        inline void removeVersion(const Version* version) noexcept{
            assert(fversions.size() > 1);
            removeVersion(index(version));
        }

        /**
         * @brief Returns UUID of current entry.
         */
        inline const Uuid& uuid() const{
            return fuuid;
        }

    private:
        /**
         * @brief Internal-use constructor used when deserializing an entry.
         * @param parent parent group for an entry.
         *
         * It leaves the UUID unintialized, and it leaves version list empty.
         * Both need to be filled by external code before passing created object to
         * the library user.
         */
        inline Entry(Group* parent) noexcept
            :fuuid(DoNotInit),
              fparent(parent)
        {}

        /**
         * @brief Internal-use constructor used when deserializing an entry.
         * @param parent parent group for an entry.
         * @param current The version to be added to constructed entry.
         *
         * It leaves the UUID unintialized. It needs to be filled by external
         * code before passing created object to the library user.
         */
        inline Entry(Group* parent, Version::Ptr current) noexcept
            :fparent(parent)
        {
            current->fparent = this;
            fversions.push_back(std::move(current));
        }

        /**
         * @brief Internal-use constructor.
         * @param parent parent group for an entry;
         * @param uuid An UUID for constructed entry;
         * @param current The version to be added to constructed entry.
         */
        inline Entry(Group* parent, Uuid uuid, Version::Ptr current)
            :fuuid(uuid),
              fparent(parent)
        {
            current->fparent = this;
            fversions.push_back(std::move(current));
        }

        /** @brief Adds a version into a database.
         * @param version An owning pointer to a version object. This parameter cannot be \p nullptr.
         * @param index Represents a position at which new version is inserted into
         *        entries internal version list. Valid indexes are in [0, versions()].
         * @param model Database model object that owns database that takes
         *        ownership of this version object. This pointer cannot be
         *        nullptr.
         *
         * Internal function called when inserting a version into entry owned
         * by a database using a database model.
         * It ensures that custom icon of a version is inserted into the database.
         */
        void addVersion(Version::Ptr version, size_t index, DatabaseModel* model);

        /** @brief Internal function called when removing an entry from database.
         *
         * Internal function called when removing an entry from database.
         * It ensures that database metadata gets updated.
         */
        void clearDatabase();

        /** @brief Internal function called when inserting an entry into a
         *         database.
         * @param database Database that takes ownership of this version object.
         *        This pointer cannot be nullptr;
         * @param args Additional parameters. For now, it can only be empty, or
         *        a pointer to a DatabaseModel object that manges the database.
         *
         * Internal function called when inserting an entry into database.
         * It ensures that database model object gets notified of any metadata updates
         * this operation my cause.
         */
        template <typename ...Args>
        void setDatabase(Database* database, Args... args);

        Uuid fuuid;
        Group* fparent;
        std::vector<Version::Ptr> fversions;

        friend class Internal::Parser<Entry>;
        friend class Group;
        friend class Database;
        friend class DatabaseModel;
    };

    /**
     * @brief The Group class represents a database directory.
     *
     * It can be owned by at most one group at a time, and it can own any number
     * of groups (called here subgroups) and any number of entries. Every group
     * holds 2 internal lists: one containing pointers to owned groups, and one
     * containing pointers to owned entries.
     */
    class Group{
    public:
        /**
         * @brief Ptr is an unique owning pointer to a Group object.
         *
         * It releases pointed object when it goes out of scope.
         */
        typedef std::unique_ptr<Group> Ptr;

        /** @brief Group properties.
         *
         * This structure is used to describe user-visible properties of a group.
         */
        class Properties{
        public:
            typedef std::unique_ptr<Properties> Ptr;

            std::string name;
            std::string notes;
            std::string defaultAutoTypeSequence;
            Icon icon;
            Times times;
            Uuid lastTopVisibleEntry;
            bool isExpanded;
            bool enableAutoType;
            bool enableSearching;

            /** @brief Constructs uninitilized properties objects.
             *
             * Field of constructed object are default-initialized.
             * This means that entries of the structure are not set to any specific
             * values (except name, notes and defaultAutoTypeSequence, wchich are
             * empty strings).
             *
             * This constructor is useful if fields are to be
             * assigned directly after construction anyway.
             */
            inline Properties(DoNotInitEnum val) noexcept
                :times(val),
                  lastTopVisibleEntry(val)
            {}

            /** @brief Creates default group properieties.
             *
             * Default group properties are:
             *   - name, notes and defaultAutoTypeSequence are empty.
             *   - icon is set to StandardIcon::Folder
             *   - isExpanded, enableAutoType and enableSearching are set to true.
             */
            inline Properties() noexcept
                :icon(StandardIcon::Folder),
                   lastTopVisibleEntry(Uuid::nil()),
                   isExpanded(true),
                   enableAutoType(true),
                   enableSearching(true)
            {}
        };

        /** @brief Constructs an empty group.
         *
         * Constructed group belongs to no database and has no parent
         * group.
         * It has a default (uninitialized) UUID.
         */
        inline Group(Uuid uuid = Uuid::generate()) noexcept
            :fparent(nullptr),
              fdatabase(nullptr),
              fuuid(std::move(uuid)),
              fproperties(new Properties())
        {}

        /**
         * @brief Group copy constructor.
         * @param group Group to be copied.
         *
         * Performs deep copy of a group. All group, entry and version objects owned
         * by \p group are copied and inserted in the subtree of newly creted group
         * in the same way as the original. All subgroup entry and version copies
         * belog to no database, and group and entry copies have new-generated UUIDs.
         *
         * Resulting group belongs to no database, and has a new-generated UUID.
         */
        Group(const Group& group);

        /**
         * @brief UUID of a group.
         */
        const Uuid& uuid() const noexcept{ return fuuid; }

        /**
         * @brief Properties of a group.
         */
        const Properties& properties() const noexcept{ return *fproperties.get(); }

        /**
         * @brief Properties of a group.
         */
        Properties& properties() noexcept{ return *fproperties.get(); }


        /**
         * @brief Replaces properties of a group with a copy of provided object.
         * @param properties New properties of a group. This pointer cannot be nullptr.
         * @return Pointer to old properties object. This pointer is never nullptr.
         */
        inline Properties::Ptr setProperties(Properties::Ptr properties){
            using std::swap;
            swap(fproperties, properties);
            return properties;
        }

        /**
         * @brief Parent group for a group.
         *
         * Parent of a group is the group that owns that group. If a group is not owned
         * by any group, this method returns \p nullptr.
         */
        inline Group* parent() noexcept { return fparent; }

        /** @copydoc parent()
         *
         * This a const-overload method.
         */
        inline const Group* parent() const noexcept { return fparent; }

        /**
         * @brief Owner database for a group.
         *
         * Owner databaser of a group is the database that owns that group (directly or
         * indirectly). If a group is not owned by any database, this method returns
         * \p nullptr.
         */
        inline Database* database() noexcept { return fdatabase; }

        /** @copydoc database()
         *
         * This a const-overload.
         */
        inline const Database* database() const noexcept { return fdatabase; }

        /**
         * @brief Returns index of a group in it's parent group.
         *
         * If a group has no parent group, result is undefined behavior.
         *
         * @return Index of a group in it's parent group.
         */
        inline size_t index() const noexcept{
            return parent()->index(this);
        }

        /**
         * @brief Checks wheter a group is an ancestor to this group.
         * @param group Group that might be an ancestor to this group.
         *
         * Group is ancestor to another group object if it owns that group or it
         * owns another ancestor of that group.
         *
         * @return \p true if \p group is an ancestor to this group; \p false
         * otherwise.
         */
        bool ancestor(const Group* group) const noexcept;

        /**
         * @brief Returns index of a group in current group.
         * @param group Group owned by current group.
         *
         * If \p group is not a direct subgroup of current group, result is undefined behavior.
         *
         * @return Index of \p group in current group.
         */
        size_t index(const Group* g) const noexcept;

        /**
         * @brief Returns index of an entry in current group.
         * @param entry Entry oned by current group.
         *
         * If \p e is not owned by current group, result is undefined behavior.
         *
         * @return Index of \p e in current group.
         */
        size_t index(const Entry* e) const noexcept;

        /**
         * @brief Removes a group from it's parent group.
         *
         * If group has no parent group, result is undefined behavior.
         *
         * It has the same effect as parent()->removeGroup(this);
         */
        inline void remove() noexcept{
            parent()->removeGroup(this);
        }

        /**
         * @brief Removes a group from it's parent group.
         *
         * If group has no parent group, result is undefined behavior.
         *
         * It has the same effect as parent()->takeGroup(this);
         */
        inline Ptr take() noexcept{
            return parent()->takeGroup(this);
        }

        /**
         * @brief The number of subgroups in this group.
         */
        inline size_t groups() const noexcept{
            return fgroups.size();
        }

        /**
         * @brief Returns subgroup at specified index.
         * @param index Index of a group object to retrieve. Valid indexes are in [0, groups()).
         *
         * @return This method never returns nullptr.
         *
         * If specified index is outside valid range, it results in undefined behavior.
         */
        inline const Group* group(size_t index) const noexcept{
            return fgroups.at(index).get();
        }

        /**
         * @brief Returns subgroup at specified index.
         * @param index Index of a group object to retrieve. Valid indexes are in [0, groups()).
         *
         * @return This method never returns nullptr.
         *
         * If specified index is outside valid range, it results in undefined behavior.
         */
        inline Group* group(size_t index) noexcept{
            return fgroups.at(index).get();
        }

        /**
         * @brief Returns a subgroup with specified UUID.
         * @param uuid UUID of a group object to retrieve.
         *
         * @return Group with specified UUID or nullptr if no such group exists.
         *
         * This method searches through entire subtree rooted at this group, not just
         * groups owned directly by it.
         */
        inline Group* group(const Uuid& uuid) noexcept{
            return groupLookup(uuid);
        }

        /**
         * @brief Returns a subgroup with specified UUID.
         * @param uuid UUID of a group object to retrieve.
         *
         * @return Group with specified UUID or nullptr if no such group exists.
         *
         * This method searches through entire subtree rooted at this group, not just
         * groups owned directly by it.
         */
        inline const Group* group(const Uuid& uuid) const noexcept{
            return groupLookup(uuid);
        }

        /** @brief Adds a new subgroup to current group.
         * @param group Owning pointer to a group object. This pointer cannot be nullptr.
         * @param index Position at which new subgroup should be inserted into internal subgroup list.
         *        Valid values are [0, groups()].
         */
        void addGroup(Group::Ptr group, size_t index);

        /** @brief Removes a subgroup and returns ownership of it to the caller.
         * @param index Position of a group (in internal subgroup list) that is to be
         *        removed.
         * @return An owning pointer to removed group.
         *
         * Returned group belongs to no database and has no parent group.
         *
         * If returned group was owned by a database and was set as recycle bin
         * group for that database, then recycle bin group for that database is set
         * to \p nullptr with timestamp as reported by time().
         * If returned group was owned by a database and was set as templates
         * group for that database, then templates group for that database is set
         * to \p nullptr with timestamp as reported by time().
         */
        Group::Ptr takeGroup(size_t index) noexcept;

        /** @brief Removes a subgroup and returns ownership of it to the caller.
         * @param group Non-owning pointer to the subgroup to be removed. This pointer cannot be nullptr.
         *
         * Returned group belongs to no database and has no parent group.
         *
         * If returned group was owned by a database and was set as recycle bin
         * group for that database, then recycle bin group for that database is set
         * to \p nullptr with timestamp as reported by time().
         * If returned group was owned by a database and was set as templates
         * group for that database, then templates group for that database is set
         * to \p nullptr with timestamp as reported by time().
         *
         * If \p group is not directly owned by current group, result is undefined behavior.
         */
        inline Group::Ptr takeGroup(const Group* group) noexcept{
            return takeGroup(index(group));
        }

        /** @brief Removes a subgroup and destroys it.
         * @param index Position of a group (in internal subgroup list) that is to be
         *        removed and deleted.
         *
         * If returned group was owned by a database and was set as recycle bin
         * group for that database, then recycle bin group for that database is set
         * to \p nullptr with timestamp as reported by time().
         * If returned group was owned by a database and was set as templates
         * group for that database, then templates group for that database is set
         * to \p nullptr with timestamp as reported by time().
         */
        inline void removeGroup(size_t index) noexcept{
            takeGroup(index);
        }

        /** @brief Removes a subgroup and destroys it.
         * @param group Non-owning pointer to the subgroup to be removed. This pointer cannot be nullptr.
         *
         * If returned group was owned by a database and was set as recycle bin
         * group for that database, then recycle bin group for that database is set
         * to \p nullptr with timestamp as reported by time().
         * If returned group was owned by a database and was set as templates
         * group for that database, then templates group for that database is set
         * to \p nullptr with timestamp as reported by time().
         *
         * If \p group is not directly owned by current group, result is undefined behavior.
         */
        inline void removeGroup(const Group* group) noexcept{
            takeGroup(index(group));
        }

        /** @brief Moves a group to new parent group.
         * @param index Index of subgroup of current group to be moved. Valid
         *        values lie in [0, groups());
         * @param newParent pointer to Group object that should now own moved
         *        group. This pointer cannot be ancestor of current group, and
         *        it cannot be nullptr.
         * @param newIndex index of subgroup of newParent, before which current
         *        group is added to its new parent. Valid values lie in
         *        [0, newParent->groups()];
         *
         * Current group (source parent) and newParent (destination parent) may
         * be the same group. In such case, valid range for newIndex is between
         * [0, index) and (index+1, newParent->groups()]; ie. no-op moves
         * produce unknown behavior.
         */
        void moveGroup(size_t index, Group* newParent, size_t newIndex);

        /** @brief Number of entries in this group.
         */
        inline size_t entries() const noexcept{
            return fentries.size();
        }

        /**
         * @brief Returns an entry at specified index.
         * @param index Index of an entry object to retrieve. Valid indexes are in [0, entries()).
         *
         * @return Pointer to an entry object. This method never returns nullptr.
         *
         * If specified index is outside valid range, it results in undefined behavior.
         */
        inline const Entry* entry(size_t index) const noexcept{
            return fentries.at(index).get();
        }

        /**
         * @brief Returns an entry at specified index.
         * @param index Index of an entry object to retrieve. Valid indexes are in [0, entries()).
         *
         * @return Pointer to an entry object. This method never returns nullptr.
         *
         * If specified index is outside valid range, it results in undefined behavior.
         */
        inline Entry* entry(size_t index) noexcept{
            return fentries.at(index).get();
        }

        /**
         * @brief Returns an entry with specified UUID.
         * @param uuid UUID of an entry object to retrieve.
         *
         * @return Pointer to an entry object with specified UUID or nullptr if no such
         *         entry exists.
         *
         * This method searches through entire subtree rooted at this group, not just
         * entries owned directly by it.
         */
        inline Entry* entry(const Uuid& uuid) noexcept{
            return entryLookup(uuid);
        }

        /**
         * @brief Returns an entry with specified UUID.
         * @param uuid UUID of an entry object to retrieve.
         *
         * @return Pointer to an entry object with specified UUID or nullptr if no such
         *         entry exists.
         *
         * This method searches through entire subtree rooted at this group, not just
         * entries owned directly by it.
         */
        inline const Entry* entry(const Uuid& uuid) const noexcept{
            return entryLookup(uuid);
        }

        /** @brief Adds a new entry to current group.
         * @param group Owning pointer to an entry object. This pointer cannot be nullptr.
         * @param index Position at which new entry should be inserted into internal entry list.
         *        Valid values are [0, entries()].
         */
        void addEntry(Entry::Ptr entry, size_t index);

        /** @brief Removes an entry owned by this group and returns ownership of it to
         *         the caller.
         * @param index Position of an entry (in internal entry list) that is to be
         *        removed.
         * @return An owning pointer to removed entry.
         *
         * Returned entry belongs no database and has no parent group.
         */
        Entry::Ptr takeEntry(size_t index) noexcept;

        /** @brief Removes an entry and returns ownership of it to the caller.
         * @param group Non-owning pointer to the entry to be removed. This pointer cannot be nullptr.
         *
         * Returned entry belongs to no database and has no parent group.
         * If \p entry is not directly owned by current group, result is undefined behavior.
         */
        inline Entry::Ptr takeEntry(Entry* entry) noexcept{
            return takeEntry(index(entry));
        }

        /** @brief Removes an entry and destroys it.
         * @param index Position of an entry (in internal entry list) that is to be
         *        removed and deleted.
         */
        inline void removeEntry(size_t index) noexcept{
            fentries.erase(fentries.begin()+ index);
        }

        /** @brief Removes an entry and destroys it.
         * @param group Non-owning pointer to the entry to be removed. This pointer cannot be nullptr.
         *
         * If \p entry is not directly owned by current group, result is undefined behavior.
         */
        inline void removeEntry(Entry* entry) noexcept{
            return removeEntry(index(entry));
        }


        /** @brief Moves an entry to new parent group.
         * @param index Index of an entry in current group to be moved. Valid
         *        values lie in [0, entries());
         * @param newParent pointer to Group object that should now own moved
         *        entry. This pointer cannot be  nullptr;
         * @param newIndex index of an entry in newParent, before which moved
         *        entry is added to its new parent. Valid values lie in
         *        [0, newParent->entries()];
         *
         * Current group (source parent) and newParent (destination parent) may
         * be the same group. In such case, valid range for newIndex is between
         * [0, index) and (index+1, newParent->entries()]; ie. no-op moves
         * produce unknown behavior.
         */
        void moveEntry(size_t index, Group* newParent, size_t newIndex);

    private:

        /** @brief Internal method called when group is taken out of database.
         *
         * It resets internal pointer to the database from removed group and
         * all its subgroups.
         */
        void clearDatabase() noexcept;

        /** @brief Internal function called when inserting a group into database.
         * @param database Database that takes ownership of this version object.
         *        This pointer cannot be nullptr;
         * @param args Additional parameters. For now, it can only be empty, or
         *        a pointer to a DatabaseModel object that manges the database.
         *
         * Internal function called when inserting a group into database.
         * It ensures that database model object gets notified of any metadata updates
         * this operation may cause.
         */
        template <typename ...Args>
        void setDatabase(Database* database, Args... args);

        /** @brief Internal constructor. Constructs an empty group.
         *
         * Constructed group has \p parent group as parent, but is not added to the
         * \p parent's internal list. It has internal pointer to the database set to
         * the same as \p parent's.
         * It has non-initialized UUID and default-initialized properties.
         */
        inline Group(Group* parent) noexcept
            :fparent(parent),
              fdatabase(parent->fdatabase),
              fuuid(DoNotInit),
              fproperties(new Properties())
        {}

        /** @brief Internal constructor. Constructs an empty group.
         *
         * Constructed group has parent group set no nullptr. It has internal pointer
         * to the database set to \p database.
         * It has non-initialized UUID and default-initialized properties.
         */
        inline Group(Database* database) noexcept
            :fparent(nullptr),
              fdatabase(database),
              fuuid(DoNotInit),
              fproperties(new Properties())
        {}

        /** @brief Internal method that looks up a group in groups owned by this
         *         group.
         * @param uuid UUID of a group to be returned.
         * @return Pointer to a group with \uuid UUID or nullptr if no such group
         * found.
         *
         * Group for which this method called can also be returned.
         */
        Group* groupLookup(const Uuid& uuid) const noexcept;

        /** @brief Internal method that looks up an entry in entries owned by
         *         this group.
         * @param uuid UUID of an entry to be returned.
         * @return Pointer to an entry with \uuid UUID or nullptr if no such entry
         * found.
         *
         * This method searches through entries owned by this group and all its
         * subgroups.
         */
        Entry* entryLookup(const Uuid& uuid) const noexcept;

        /** @brief Adds a group into a database.
         * @param group An owning pointer to a group object. This parameter
         *        cannot be \p nullptr.
         * @param index Represents a position at which new group is inserted
         *        into group's internal sub-groups list. Valid indexes are in
         *        [0, groups()].
         * @param model Database model object that owns this group object. This
         *        pointer cannot be nullptr.
         *
         * Internal function called when inserting a sub-group into group owned
         * by a database model.
         * It ensures that database model object gets notified of any metadata
         * updates this operation my cause.
         */
        void addGroup(Group::Ptr group, size_t index, DatabaseModel* model);

        /** @brief Adds an entry into a database.
         * @param entry An owning pointer to an entry object. This parameter cannot be \p nullptr.
         * @param index Represents a position at which new entry is inserted into
         *        group's internal sub-entries list. Valid indexes are in [0, entries()].
         * @param model Database model object that owns this group object. This
         *        pointer cannot be nullptr.
         *
         * Internal function called when inserting an entry into group owned
         * by a database model.
         * It ensures that database model object gets notified of any metadata updates
         * this operation my cause.
         */
        void addEntry(Entry::Ptr entry, size_t index, DatabaseModel* model);


        Group* fparent;
        Database* fdatabase;

        Uuid fuuid;
        Properties::Ptr fproperties;

        std::vector<Group::Ptr> fgroups;
        std::vector<Entry::Ptr> fentries;

        friend class Internal::Parser<Group>;
        friend class Database;
        friend class DatabaseModel;
    };

    /** @brief Constructs an empty database.
     *
     * Empty database owns only a root group, which owns no further groups or
     * entries. Created database has no recycle bin group set, no templates group
     * set and default constructed \p Settings object, except for fields
     * Settings::nameChanged(), Settings::descriptionChanged(),
     * Settings::defaultUsernameChanged(), Settings::masterKeyChanged.
     *
     * recycleBinChanged() and templatesChanged() are set to current time (as
     * reported by time() function.).
     */
    Database();

    Database(const Database&) = delete;
    Database(Database&& database) = delete;
    Database& operator=(const Database&) = delete;
    Database& operator=(Database&&) = delete;

    /** @brief Returns non-owning pointer to the root group of database.
     *
     * Each group and entry owned by database is owned (directly or indirectly)
     * by this group.
     */
    inline Group* root() noexcept{
        return froot.get();
    }

    /** @brief Returns non-owning pointer to the root group of database.
     *
     * Each group and entry owned by database is owned (directly or indirectly)
     * by this group.
     */
    const Group* root() const noexcept{
        return froot.get();
    }

    /** @brief Returns recycle bin group or nullptr if no recycle bin was set.
     *
     * Whether recycle bin is active or not depends not only on a valid group
     * being set, but also on settings().recycleBinEnabled field.
     *
     * Recycle bin group should be used as temporary directory to which
     * deleted groups and entries are moved, and left for some time before
     * being finally deleted. If no recycle bin is set, entries and groups
     * should be deleted immediately.
     */
    inline const Group* recycleBin() const noexcept{
         return frecycleBin;
    }

    /** @brief Returns recycle bin group or nullptr if no recycle bin was set.
     *
     * Whether recycle bin is active or not depends not only on a valid group
     * being set, but also on settings().recycleBinEnabled field.
     *
     * Recycle bin group should be used as temporary directory to which
     * deleted groups and entries are moved, and left for some time before
     * being finally deleted. If no recycle bin is set, entries and groups
     * should be deleted immediately.
     */
    inline Group* recycleBin() noexcept{
         return frecycleBin;
    }

    /** @brief Sets a new recycle bin group.
     * @param bin New recycle bin Group pointer or \p nullptr.
     * @param changed Time when recycle bin group was changed. In order to avoid
     *        inconsistencies it is recomended that default value (time()) is used.
     *
     * If \p bin is a valid pointer, it must point to a group that is owned by
     * this database.
     */
    void setRecycleBin(const Group* bin, std::time_t changed = time(nullptr)) noexcept;

    /** @brief Time when recycle bin group was last set (as reported by time()).
     */
    const std::time_t& recycleBinChanged() const noexcept{
        return frecycleBinChanged;
    }

    /** @brief Returns templates group or nullptr if no templates group was set.
     *
     * Templates group is a special database group. It is recomened to user
     * interface impementers to use entries owned by this group as templates
     * to be presented to the user when creating a new entry.
     */
    inline const Group* templates() const noexcept{
         return ftemplates;
    }

    /** @brief Returns templates group or nullptr if no templates group was set.
     *
     * Templates group is a special database group. It is recomened to user
     * interface impementers to use entries owned by this group as templates
     * to be presented to the user when creating a new entry.
     */
    inline Group* templates() noexcept{
         return ftemplates;
    }

    /** @brief Sets a templates group.
     * @param templ New templates group pointer or nullptr.
     * @param changed Time when templates group was changed. In order to avoid
     *        inconsistencies it is recomended that default value (time()) is used.
     *
     * If \p templ is a valid pointer, it must point to a group that is owned by
     * this database.
     *
     */
    void setTemplates(const Group* templ, std::time_t changed = time(nullptr)) noexcept;

    /** @brief Time when templates group was last set (as reported by time()).
     */
    const std::time_t& templatesChanged() const noexcept{
        return ftemplatesChanged;
    }

    /** @brief Returns non-owning pointer to the group with specified UUID.
     * @param uuid UUID of a group object to retrieve.
     * @return Group with specified UUID or nullptr if no such group exists.
     *
     * This method searches through entire database tree.
     */
    inline Group* group(const Uuid& uuid) noexcept{
        if (froot->fuuid == uuid)
            return froot.get();
        return froot->groupLookup(uuid);
    }

    /** @brief Returns non-owning pointer to the group with specified UUID.
     * @param uuid UUID of a group object to retrieve.
     * @return Group with specified UUID or nullptr if no such group exists.
     *
     * This method searches through entire database tree.
     */
    inline const Group* group(const Uuid& uuid) const noexcept{
        if (froot->fuuid == uuid)
            return froot.get();
        return froot->groupLookup(uuid);
    }

    /** @brief Returns non-owning pointer to the entry with specified UUID.
     * @param uuid UUID of an entry object to retrieve.
     * @return Entry with specified UUID or nullptr if no such entry exists.
     *
     * This method searches through entire database tree.
     */
    inline Entry* entry(const Uuid& uuid) noexcept{
        return froot->entryLookup(uuid);
    }

    /** @brief Returns non-owning pointer to the entry with specified UUID.
     * @param uuid UUID of an entry object to retrieve.
     * @return Entry with specified UUID or nullptr if no such entry exists.
     *
     * This method searches through entire database tree.
     */
    inline const Entry* entry(const Uuid& uuid) const noexcept{
        return froot->entryLookup(uuid);
    }

    /** @brief current Settings object.
     */
    inline const Settings& settings() const noexcept{
        return *fsettings.get();
    }

    /** @brief current Settings object.
     */
    inline Settings& settings() noexcept{
        return *fsettings.get();
    }

    /** @brief Changes current settings object.
     * @return Pointer to old settings object. This pointer is never nullptr.
     */
    inline Settings::Ptr setSettings(Settings::Ptr settings){
        using std::swap;
        swap(fsettings, settings);
        return settings;
    }

    /** @brief Returns count of custom icons stored in this database.
     */
    inline size_t customIcons() const noexcept{
        return fcustomIcons.size();
    }

    /** @brief Returns a reference to a CustomIcon objech at position \p index.
     * @param index Index of custom icon to be retrieved. Valid values are in
     *        [0, customIcons()).
     */
    inline const CustomIcon::Ptr& customIcon(size_t index) const noexcept{
        return fcustomIcons.at(index);
    }

    /** @brief Returns an index of custom icon with specified UUID.
     *
     * It returns -1 if no such icon is present in database.
     */
    int customIconIndex(const Uuid& uuid) const noexcept;

    /** @brief Returns an Icon with specific UUID or a StandardIcon.
     * @param customIcon UUID of a custom icon to retrieve.
     * @param sicon standard icon to return if \p customIcon UUID does not appear
     *        in the database.
     *
     * This is an utility method. Since KDBX format can save both custom icon UUID and
     * a standard icon index, this method is provided for cases where both are present.
     * In such case custom icon takes precedence. If custom icon UUID equal Uuid::nil()
     * or icon with given UUId is not present in the database, standard icon is returned.
     */
    Icon icon(Uuid customIcon, StandardIcon sicon) const noexcept;

    /** @brief Adds a CustomIcon into the database.
     * @param icon Shared pointer to the custom icon to be added to the database.
     *        This pointer cannot be nullptr.
     * @return Icon object pointing to a CustomIcon \p icon's UUID.
     *
     * This method adds custom icon to the database only if ther is no custom icon
     * with the same UUID already in the database. In other words,  custom icons
     * are assumed to be equivalent if their UUIDs are the same. If a custom icon
     * with the same UUID was already added to the database, added \p icon is ignored,
     * and a reference to the custom icon already in the database is returned.
     */
    Icon addCustomIcon(CustomIcon::Ptr icon);

    /** @brief Adds custom icon into the database.
     * @param Icon to be added to the database.
     *
     * This is an utility method. If \p icon is a custom icon, it calls
     * addCustomIcon(icon.custom()) and returns its result. Otherwise it returns passed
     * icon object unchanged.
     */
    inline Icon addCustomIcon(const Icon& icon){
        if (icon.type() == Icon::Type::Custom)
            return addCustomIcon(icon.custom());
        return icon;
    }

    /** @brief Serializes a database into an ostream object.
     * @param file An owning pointer to an ostream object that is used to
     *        to store serialized data.
     * @param key Composite key used to encrypt serialized data. This parameter is
     *        only used if \p settings indicates that the data is to be encrypted.
     * @return future object that gets back an owning pointer to \p ostream \p file
     *         object when the serialization process is finished and the stream is
     *         flushed.
     *
     * If serialization was interrupted by an error, returned future
     * object will throw an apropriate exception in \p get() method. In such case
     * retrieving the \p ostream object is not possible.
     */
    std::future<std::unique_ptr<std::ostream>> saveToFile(std::unique_ptr<std::ostream> file, const CompositeKey& key) const;

//    /** @brief Serializes a database into an ostream object *** USING PLAIN XML FORMAT***.
//     * @param file An owning pointer to an ostream object that is used to
//     *        to store serialized data.
//     * @return future object that gets back an owning pointer to \p ostream \p file
//     *         object when the serialization process is finished and the stream is
//     *         flushed.
//     *
//     * This method is mainly useful for debugging serialization process, as sensitive
//     * data should never be saved to disk without protection.
//     * If serialization was interrupted by an error, returned future
//     * object will throw an apropriate exception in \p get() method. In such case
//     * retrieving the \p ostream object is not possible.
//     */
//    std::future<std::unique_ptr<std::ostream>> saveToXmlFile(std::unique_ptr<std::ostream> file) const;

    /** @brief Reads in a KDBX file headers from \p file.
     * @param file Owning pointer to an istream object that is to be read.
     *
     * This method reads headers of a KDBX-formated input and returns a File object
     * that can be used in order to deserialize database object.
     */
    static File loadFromFile(std::unique_ptr<std::istream> file);

    /** @brief This method is necesary to initialize some external libraries used
               When serializing and deserializing datbases.
        It should be called at least once before saveToFile, saveToXmlFile or
        loadFromFile methods are called.*/
    static void init() noexcept;
private:

    Group::Ptr froot;
    std::map<Uuid, time_t> fdeletedObjects;
    Settings::Ptr fsettings;
    CustomIcons fcustomIcons;
    SafeVector<uint8_t> compositeKey;

    Group* frecycleBin;
    Group* ftemplates;
    std::time_t frecycleBinChanged;
    std::time_t ftemplatesChanged;

    std::map<std::string, std::string> customData;

    friend class Internal::Parser<Database>;
    friend class Internal::Parser<Meta>;
    friend class Group;
    friend class Entry;
};



}

#endif // KDBXDATABASE_H
