/*Copyright (C) 2016 Jaroslaw Kubik
 *
   This file is part of libkeepass2pp library.

libkeepass2pp is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
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
};

class CompositeKey;

class BasicDatabaseModel;
template <typename ModelType>
class DatabaseModel;

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

    class Entry;
    class Group;
    class Meta;

    /** @brief Global database settings.
     *
     * This class is storing database global settings.
     */
    class Settings{
    public:

        /** @brief Constructs uninitilized settings objects.
         *
         * Field of constructed object are default-initialized.
         * This means that entries of the structure are not set to any specific
         * values (except databaseName, databaseDescription, defaultUsername and
         * color, which are empty strings).
         *
         * This constructor is useful if fields are to be assigned after construction
         * anyway.
         */
        Settings(DoNotInitEnum val)
            :recycleBinUUID(val),
              entryTemplatesGroup(val),
              lastSelectedGroup(val),
              lastTopVisibleGroup(val)
        {}

        //ToDo: rethink default values here.
        /** @brief Initializes settings to default values.
         *
         * Default values are:
         *  - databaseName, databaseDescription, defaultUsername and color are set
         *    to empyt strings.
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
        inline Settings()
            :databaseNameChanged(0),
              databaseDescriptionChanged(0),
              defaultUsernameChanged(0),
              masterKeyChanged(0),
              recycleBinChanged(0),
              entryTemplatesGroupChanged(0),
              maintenanceHistoryDays(365),
              historyMaxItems(-1),
              masterKeyChangeRec(-1),
              masterKeyChangeForce(-1),
              historyMaxSize(-1),
              memoryProtection(1 << std::size_t(MemoryProtection::Password)),
              recycleBinEnabled(false)
        {}

        Settings(Settings&&) = default;
        Settings& operator=(Settings&&) = default;
        Settings(const Settings&) = delete;

        std::string databaseName;
        std::string databaseDescription;
        std::string defaultUsername;
        std::string color; // just a raw string for now...
        std::time_t databaseNameChanged;
        std::time_t databaseDescriptionChanged;
        std::time_t defaultUsernameChanged;
        std::time_t masterKeyChanged;
        std::time_t recycleBinChanged;
        std::time_t entryTemplatesGroupChanged;
        unsigned int maintenanceHistoryDays;
        int historyMaxItems;
        int64_t masterKeyChangeRec;
        int64_t masterKeyChangeForce;
        int64_t historyMaxSize;
        MemoryProtectionFlags memoryProtection;
        Uuid recycleBinUUID;
        Uuid entryTemplatesGroup;
        Uuid lastSelectedGroup;
        Uuid lastTopVisibleGroup;
        bool recycleBinEnabled;
    };

    /** @brief The Version class represents a version of a database entry.
     *
     * A version can be owned by at most one entry at a time.
     */
    class Version{
    private:
        /** @brief Version constructor used only internally when deserializing
         * a database.
         * @param parent Parent entry of constructed version object.
         *        This pointer cannot be nullptr.
         */
        inline Version(Entry* parent) noexcept
            :fparent(parent)
        {}

        void setDatabase(Database* model);


        /** @brief Adds a version into a database.
         * @param model Database model object that owns database that takes
         *        ownership of this version object.
         *        This pointer cannot be nullptr.
         *
         * Internal function called when inserting version, entry or group into
         * a database.
         * It ensures that database model object gets notified of any metadata updates
         * this operation my cause.
         */
        void setDatabase(BasicDatabaseModel* model);

        Entry* fparent;

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
         * except icon, that is set to Kdbx::StandardIcon::Key standard icon.
         *
         */
        inline Version() noexcept
            :fparent(0),
              icon(StandardIcon::Key)
        {}

        /**
         * @brief Copy constructor for a Version object.
         *
         * Constructed object contains copies of all public variables of object
         * v, but it doesn't belong to any entry.
         *
         * @note Version that doesn't beling to any entry cannot belong to a group
         *       or a database.
         */
        inline Version(const Version& v)
            :fparent(0),
              icon(v.icon),
              fgColor(v.fgColor),
              bgColor(v.bgColor),
              overrideUrl(v.overrideUrl),
              tags(v.tags),
              times(v.times),
              strings(v.strings),
              binaries(v.binaries),
              autoType(v.autoType)
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

        friend class Entry;
        friend class Database;
        friend class Internal::Parser<Version>;
        friend class BasicDatabaseModel;
    };

    /**
     * @brief The Entry class represents a database entry.
     *
     * It can be owned by at most one group at a time, and it must own at least
     * one Version object. Every entry holds internal vector of pointers to owned
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
              fparent(0)
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
              fparent(0)
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
         * @param version An owning pointer to a version object. This parameter cannot be \p nullptr.
         * @param index Represents a position at which new version is inserted into
         *        entries internal version list. Valid indexes are in [0, versions()].
         *
         * Entry takes ownership of the provided version object and inserts it into
         * internal list of version at position \p index.
         */
        void addVersion(Version::Ptr version, size_t index);

        /**
         * @brief Removes a version at postion \p index from an entry.
         * @param index index of a version object to be taken.
         *
         * It returns an ownership of removed version object to the caller.
         */
        inline Version::Ptr takeVersion(size_t index) noexcept{
            assert(fversions.size() > 1);
            Version::Ptr result = std::move(fversions.at(index));
            fversions.erase(fversions.begin() + index);
            result->fparent = 0;
            return result;
        }

        /**
         * @brief Removes a version from an entry.
         * @param version Version object to be taken. It must be owned by an entry
         *        is taken from.
         *
         * It returns an ownership of removed version object to the caller.
         * If \p version is not owned by an entry on which this method was called,
         * result is undefined behavior.
         */
        inline Version::Ptr takeVersion(const Version* version) noexcept{
            assert(fversions.size() > 1);
            return takeVersion(index(version));
        }

        /**
         * @brief Removes a version at postion \p index from an entry.
         * @param index index of a version object to be removed
         *
         */
        inline void removeVersion(size_t index) noexcept{
            assert(fversions.size() > 1);
            fversions.erase(fversions.begin() + index);
        }

        /**
         * @brief Removes a version from an entry.
         * @param version Version object to be removed. It must be owned by an entry
         *        is taken from.
         *
         * It deletes removed verion object.
         * If \p version is not owned by an entry on which this method was called,
         * result is undefined behavior.
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
         * @param parent parent group for an entry.
         * @param current The version to be added to constructed entry.
         *
         * It leaves the UUID unintialized. It needs to be filled by external
         * code before passing created object to the library user.
         */
        inline Entry(Group* parent, Uuid uuid, Version::Ptr current)
            :fuuid(uuid),
              fparent(parent)
        {
            current->fparent = this;
            fversions.push_back(std::move(current));
        }

        /** @brief Adds a version into a database.
         * @param model Database model object that owns database that takes
         *        ownership of this version object. This pointer cannot be nullptr.
         * @param version An owning pointer to a version object. This parameter cannot be \p nullptr.
         * @param index Represents a position at which new version is inserted into
         *        entries internal version list. Valid indexes are in [0, versions()].
         *
         * Internal function called when inserting a version into entry owned
         * by a database using a database model.
         * It ensures that custom icon of a version is inserted into the database.
         */
        void addVersion(Version::Ptr version, size_t index, BasicDatabaseModel* model);

        /** @brief Internal function called when removing an entry from database.
         * @param database Database that loses ownership of this entry object.
         *        This pointer cannot be nullptr.
         *
         * Internal function called when removing an entry from database.
         * It ensures that database metadata gets updated.
         */
        void clearDatabase(Database* database);

        /** @brief Internal function called when inserting an entry into database.
         * @param database Database that takes ownership of this entry object.
         *        This pointer cannot be nullptr.
         *
         * Internal function called when inserting an entry into database.
         * It ensures that database metadata gets updated.
         */
        void setDatabase(Database* database);


        /** @brief Internal function called when inserting an entry into database.
         * @param model Database model that takes ownership of this entry object.
         *        This pointer cannot be nullptr.
         *
         * Internal function called when inserting an entry into database.
         * It ensures that database model object gets notified of any metadata updates
         * this operation my cause.
         */
        void setDatabase(Database* database, BasicDatabaseModel* model);

        Uuid fuuid;
        Group* fparent;
        std::vector<Version::Ptr> fversions;

        friend class Internal::Parser<Entry>;
        friend class Group;
        friend class Database;
        friend class BasicDatabaseModel;
    };

    class Group{
    public:
        typedef std::unique_ptr<Group> Ptr;

    private:

        /** @brief Internal method called when group is taken out of database.
         *
         * It resets internal pointer to the database from removed group and
         * all its subgroups.
         */
        void clearDatabase() noexcept;

        /** @brief Internal methd called when gorup is added to the database.
         *
         * It sets internal pointer to the database in added group and all its
         * subrgoups. It adds all custom icons contained in versions owned
         * by added group to the database, and removed all added UUID from deleted
         * object list (if present).
         */
        void setDatabase(Database* database);

        /** @brief Internal function called when inserting a group into database.
         * @param model Database model that takes ownership of this group object.
         *        This pointer cannot be nullptr.
         *
         * Internal function called when inserting a group into database.
         * It ensures that database model object gets notified of any metadata updates
         * this operation may cause.
         */
        void setDatabase(Database* database, BasicDatabaseModel* model);

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
              fuuid(DoNotInit)
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
              fuuid(DoNotInit)
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
         * @param model Database model object that owns this group object. This pointer
         *        cannot be nullptr.
         * @param group An owning pointer to a group object. This parameter cannot be \p nullptr.
         * @param index Represents a position at which new group is inserted into
         *        group's internal sub-groups list. Valid indexes are in [0, groups()].
         *
         * Internal function called when inserting a sub-group into group owned
         * by a database model.
         * It ensures that database model object gets notified of any metadata updates
         * this operation my cause.
         */
        void addGroup(Group::Ptr group, size_t index, BasicDatabaseModel* model);


        /** @brief Adds an entry into a database.
         * @param model Database model object that owns this group object. This pointer
         *        cannot be nullptr.
         * @param entry An owning pointer to an entry object. This parameter cannot be \p nullptr.
         * @param index Represents a position at which new entry is inserted into
         *        group's internal sub-entries list. Valid indexes are in [0, entries()].
         *
         * Internal function called when inserting an entry into group owned
         * by a database model.
         * It ensures that database model object gets notified of any metadata updates
         * this operation my cause.
         */
        void addEntry(Entry::Ptr entry, size_t index, BasicDatabaseModel* model);


    public:

        /** @brief Group properties.
         *
         * This structure is used to describe user-visible properties of a group.
         */
        class Properties{
        public:
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
              fuuid(std::move(uuid))
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

        //ToDo: properties as a pointer? The structure is not-small...
        /**
         * @brief Properties of a group.
         */
        const Properties& properties() const noexcept{ return fproperties; }

        /**
         * @brief Replaces properties of a group with a copy of provided object.
         * @param properties New properties of a group.
         */
        inline void setProperties(const Properties& properties){
            fproperties = properties;
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
         * Group is ancestor to another group object if it is the same group,
         * it owns that group or it owns another ancestor of that group.
         *
         * @return \p true if \p group is an ancestor to this group; \p false otherwise.
         */
        bool ancestor(const Group* group) const noexcept;

        /**
         * @brief The number of subgroups in this group.
         */
        inline size_t groups() const noexcept{
            return fgroups.size();
        }

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
         * It destroys group object.
         */
        inline void remove() noexcept{
            parent()->removeGroup(this);
        }

        /**
         * @brief Removes a group from it's parent group.
         *
         * If group has no parent group, result is undefined behavior.
         *
         * It removes group object from it's parent group and returns
         * ownership of it to the caller.
         */
        inline Ptr take() noexcept{
            return parent()->takeGroup(this);
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
         * @brief Returns subgroup with specified UUID.
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
         * @brief Returns subgroup with specified UUID.
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

        void addGroup(Group::Ptr group, size_t index);

        Group* addGroup(size_t index);

        Group::Ptr takeGroup(size_t index) noexcept;

        inline Group::Ptr takeGroup(const Group* group) noexcept{
            return takeGroup(index(group));
        }

        inline void removeGroup(size_t index) noexcept{
            takeGroup(index);
        }

        inline void removeGroup(const Group* group) noexcept{
            takeGroup(index(group));
        }

        inline size_t entries() const noexcept{
            return fentries.size();
        }

        inline const Entry* entry(size_t index) const noexcept{
            return fentries.at(index).get();
        }

        inline Entry* entry(size_t index) noexcept{
            return fentries.at(index).get();
        }

        inline Entry* entry(const Uuid& uuid) noexcept{
            return entryLookup(uuid);
        }

        inline const Entry* entry(const Uuid& uuid) const noexcept{
            return entryLookup(uuid);
        }

        void addEntry(Entry::Ptr entry, size_t index);
        Entry::Ptr takeEntry(size_t index) noexcept;

        inline Entry::Ptr takeEntry(Entry* entry) noexcept{
            return takeEntry(index(entry));
        }

        inline void removeEntry(size_t index) noexcept{
            fentries.erase(fentries.begin()+ index);
        }

        inline void removeEntry(Entry* entry) noexcept{
            return removeEntry(index(entry));
        }

    private:
        Group* fparent;
        Database* fdatabase;

        Uuid fuuid;
        Properties fproperties;

        std::vector<Group::Ptr> fgroups;
        std::vector<Entry::Ptr> fentries;

        friend class Internal::Parser<Group>;
        friend class Database;
        friend class BasicDatabaseModel;
    };

/*    class DeletedObject{
    public:
        inline DeletedObject(Uuid uuid, std::time_t deletionTime) noexcept
            :uuid(std::move(uuid)),
              deleteionTime(deletionTime)
        {}

        inline bool operator==(const DeletedObject& object) const noexcept{
            return uuid == object.uuid;
        }

        inline bool operator!=(const DeletedObject& object) const noexcept{
            return uuid != object.uuid;
        }

        inline bool operator<(const DeletedObject& object) const noexcept{
            return uuid < object.uuid;
        }

        inline bool operator>(const DeletedObject& object) const noexcept{
            return uuid > object.uuid;
        }

        inline bool operator<=(const DeletedObject& object) const noexcept{
            return uuid <= object.uuid;
        }

        inline bool operator>=(const DeletedObject& object) const noexcept{
            return uuid >= object.uuid;
        }

        const Uuid uuid;
        const std::time_t deleteionTime;
    };*/

    Database();

    Database(const Database&) = delete;
    Database(Database&& database) = delete;
    Database& operator=(const Database&) = delete;
    Database& operator=(Database&&) = delete;

    inline ~Database() noexcept{}

    inline Group* root() noexcept{
        return froot.get();
    }

    const Group* root() const noexcept{
        return froot.get();
    }

    inline Group* group(const Uuid& uuid) noexcept{
        if (froot->fuuid == uuid)
            return froot.get();
        return froot->groupLookup(uuid);
    }

    inline const Group* group(const Uuid& uuid) const noexcept{
        if (froot->fuuid == uuid)
            return froot.get();
        return froot->groupLookup(uuid);
    }

    inline Entry* entry(const Uuid& uuid) noexcept{
        return froot->entryLookup(uuid);
    }

    inline const Entry* entry(const Uuid& uuid) const noexcept{
        return froot->entryLookup(uuid);
    }

    /*inline const Uuid& recycleBinUuid() const{ return fsettings.recycleBinUUID; }
    inline const Uuid& entryTemplatesGroup() const noexcept{ return fsettings.entryTemplatesGroup; }
    inline const Uuid& lastSelectedGroup() const noexcept{ return fsettings.lastSelectedGroup; }
    inline const Uuid& lastTopVisibleGroup() const noexcept{ return fsettings.lastTopVisibleGroup; }
    inline const std::string& name() const noexcept{ return fsettings.databaseName; }
    inline const std::string& description() const noexcept{ return fsettings.databaseDescription; }
    inline const std::string& defaultUsername() const noexcept{ return fsettings.defaultUsername; }
    inline const std::string& color() const noexcept{ return fsettings.color; }
    // What is this anyway? Color of an icon bacground?
    // Have I ever seen a feature that is more useless
    // but has a noticeable effect?
    inline std::time_t nameChanged() const noexcept{ return fsettings.databaseNameChanged; }
    inline std::time_t descriptionChanged() const noexcept{ return fsettings.databaseDescriptionChanged; }
    inline std::time_t defaultUsernameChanged() const noexcept{ return fsettings.defaultUsernameChanged; }
    inline std::time_t masterKeyChanged() const noexcept{ return fsettings.masterKeyChanged; }
    inline std::time_t recycleBinChanged() const noexcept{ return fsettings.recycleBinChanged; }
    inline std::time_t entryTemplatesGroupChanged() const noexcept{ return fsettings.entryTemplatesGroupChanged; }
    inline MemoryProtectionFlags memoryProtection() const noexcept{ return fsettings.memoryProtection; }
    inline bool recycleBinEnabled() const noexcept{ return fsettings.recycleBinEnabled; }
    inline int historyMaxItems() const noexcept{ return fsettings.historyMaxItems; }
    inline unsigned int maintenanceHistoryDays() const noexcept{ return fsettings.maintenanceHistoryDays; }
    inline int64_t masterKeyChanges() const noexcept{ return fsettings.masterKeyChangeRec; }
    inline int64_t masterKeyChangForce() const noexcept{ return fsettings.masterKeyChangeForce; }
    inline int64_t historyMaxSize() const noexcept{ return fsettings.historyMaxSize; }
*/
    inline const Settings& settings() const noexcept{
        return fsettings;
    }

    inline void setSettings(Settings settings){
        fsettings = std::move(settings);
    }

    //ToDo: figure out a way to purge unused custom icons on-demand.
    inline size_t customIcons() const noexcept{
        return fcustomIcons.size();
    }

    inline const CustomIcon::Ptr& customIcon(size_t index) const noexcept{
        return fcustomIcons.at(index);
    }

    int customIconIndex(const Uuid& uuid) const noexcept;

    Icon icon(Uuid customIcon, StandardIcon sicon) const noexcept;
    Icon addCustomIcon(CustomIcon::Ptr icon);

    inline Icon addCustomIcon(const Icon& icon){
        if (icon.type() == Icon::Type::Custom)
            return addCustomIcon(icon.custom());
        return icon;
    }

    class File{
    public:
        enum class CompressionAlgorithm: uint32_t
        {
            /// No compression.
            None = 0,

            /// GZip compression.
            GZip = 1,

            Count = 2
        };

        struct Settings{
            bool encrypt;
            bool compress;
            std::array<uint8_t, 16> cipherId;
            uint64_t transformRounds;
            KdbxRandomStream::Algorithm crsAlgorithm;
            CompressionAlgorithm compression;

            inline Settings() noexcept
                :encrypt(false),
                  compress(false),
                  transformRounds(0),
                  crsAlgorithm(KdbxRandomStream::Algorithm::Salsa20),
                  compression(CompressionAlgorithm::None)
            {}

        };

    private:
        std::unique_ptr<std::istream> ffile;

        std::array<uint8_t, 32> masterSeed;
        std::array<uint8_t, 32> transformSeed;
        std::array<uint8_t, 16> encryptionIV;
        std::array<uint8_t, 32> streamStartBytes;

        std::vector<uint8_t> protectedStreamKey; // what is this?


    public:
        Settings settings;

        bool needsKey();
        std::future<Database::Ptr> getDatabase(const CompositeKey& key);

        friend class Database;
    };

    std::future<void> saveToFile(std::unique_ptr<std::ostream> file, const CompositeKey& key, const File::Settings& settings) const;
    std::future<void> saveToXmlFile(std::unique_ptr<std::ostream> file) const;

    static File loadFromFile(std::unique_ptr<std::istream> file);

    static void init() noexcept;
private:

    /** @brief constructs an empty database. */
    inline Database(DoNotInitEnum)
    {}

    Group::Ptr froot;
    std::map<Uuid, time_t> fdeletedObjects;
    Settings fsettings;
    CustomIcons fcustomIcons;

    std::map<std::string, std::string> customData;

    friend class Internal::Parser<Database>;
    friend class Internal::Parser<Meta>;
    friend class Group;
    friend class Entry;
};



}

#endif // KDBXDATABASE_H
