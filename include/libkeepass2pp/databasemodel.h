#ifndef DATABASEMODEL_H
#define DATABASEMODEL_H

#include "database.h"

namespace Kdbx{

/** @brief This a base class for database models.
 *
 * Database model is a class that is used to proxy all database modyfications in case
 * it is required to sychronize such modifications with some external state. It provides
 * generic way in which algorithms can be written to work on database objects without
 * any knowledge of existence or function of such proxy.
 *
 * Database model takes ownership of database that it works on. For as long as model
 * owns a database, any mutating (non-const) access to database fields and methods is
 * considered to produce unknown behavior.
 */
class DatabaseModel{
public:

    template <typename ItemType>
    class Index{
    private:
        ItemType* fitem;
        DatabaseModel* fmodel;

    protected:

        inline Index(ItemType* group, DatabaseModel* model) noexcept
            :fitem(group),
              fmodel(model)
        {}

        inline Index(void* raw, DatabaseModel* model) noexcept
            :fitem(reinterpret_cast<ItemType*>(raw)),
              fmodel(model)
        {}

        inline ItemType* item() const noexcept{
            return fitem;
        }

    public:

        Index(const Index& index) = default;
        Index& operator=(const Index& index) = default;

        inline Index() noexcept
            :fitem(nullptr),
              fmodel(nullptr)
        {}

        inline const ItemType* get() const noexcept{
            return fitem;
        }

        inline operator ItemType*() const noexcept{
            return fitem;
        }

        inline DatabaseModel* model() const noexcept{
            return fmodel;
        }

        inline void* raw() const noexcept{
            return reinterpret_cast<void*>(fitem);
        }

        inline bool valid() const noexcept{
            return fitem;
        }

        inline const ItemType* operator->() const noexcept{
            return fitem;
        }

        inline explicit operator bool() const{
            return fitem;
        }

        inline bool operator!() const{
            return !fitem;
        }

        inline bool operator==(const Index<ItemType>& index) const noexcept{
            return fitem == index.fitem;
        }

        inline bool operator!=(const Index<ItemType>& index) const noexcept{
            return fitem != index.fitem;
        }

        inline bool operator<(const Index<ItemType>& index) const noexcept{
            return fitem < index.fitem;
        }

        inline bool operator>(const Index<ItemType>& index) const noexcept{
            return fitem > index.fitem;
        }

        inline bool operator<=(const Index<ItemType>& index) const noexcept{
            return fitem <= index.fitem;
        }

        inline bool operator>=(const Index<ItemType>& index) const noexcept{
            return fitem >= index.fitem;
        }

        friend class DatabaseModel;
    };

    class Group;
    class Entry;
    class Version;

    class Group: public Index<Database::Group>{
    protected:
        using Index<Database::Group>::Index;

    public:

        /**
         * @copydoc Database::Group::properties()
         */
        inline const Database::Group::Properties& properties() const{
            return this->item()->properties();
        }

        /**
         * @copydoc Database::Group::setProperties()
         */
        inline void setProperties(Database::Group::Properties::Ptr properties) const{
            this->model()->setProperties(this->item(), std::move(properties));
        }

        /**
         * @copydoc Database::Group::parent()
         *
         * @return Group index of parent group.
         */
        inline Group parent() const noexcept{
            return Group(this->item()->parent(), this->model());
        }

        /**
         * @copydoc Database::Group::index()
         */
        inline size_t index() const noexcept{
            return this->get()->index();
        }

        /**
         * @copydoc Database::Group::remove()
         *
         * It renders group index invalid.
         */
        inline void remove() const{
            parent().removeGroup(index());
        }

        inline size_t entries() const noexcept{
            return this->item()->entries();
        }

        inline size_t groups() const noexcept{
            return this->item()->groups();
        }

        /**
         * @copydoc Database::Group::index(const Database::Group*)
         */
        inline size_t index(const Database::Group* g) const noexcept{
            return this->get()->index(g);
        }

        /**
         * @copydoc Database::Group::index(const Database::Entry*)
         */
        inline size_t index(const Database::Entry* e) const noexcept{
            return this->get()->index(e);
        }

        inline Group group(size_t index) const noexcept{
            return Group(this->item()->group(index), this->model());
        }

        inline Entry entry(size_t index) const noexcept{
            return Entry(this->item()->entry(index), this->model());
        }

        inline Group addGroup(Database::Group::Ptr group, size_t index) const{
            return Group(this->model()->addGroup(this->item(), std::move(group), index), this->model());
        }

        inline Entry addEntry(Database::Entry::Ptr entry, size_t index) const{
            return Entry(this->model()->addEntry(this->item(), std::move(entry), index), this->model());
        }

        inline void removeGroup(size_t index) const{
            this->model()->removeGroup(this->item(), index);
        }

        inline void removeEntry(size_t index) const{
            this->model()->removeEntry(this->item(), index);
        }

        friend class DatabaseModel;
        friend class Entry;
    };

    class Entry: public Index<Database::Entry>{
    protected:
        using Index<Database::Entry>::Index;

    public:

        /**
         * @copydoc Database::Entry::parent()
         *
         * @return Group index of parent group.
         */
        inline Group parent() const noexcept{
            return Group(this->item()->parent(), this->model());
        }

        /**
         * @copydoc Database::Entry::index()
         */
        size_t index() const noexcept{
            return this->get()->index();
        }

        /**
         * @copydoc Database::Entry::remove()
         *
         * It renders entry index invalid.
         */
        inline void remove() const{
            parent().removeEntry(index());
        }

        inline size_t versions() const noexcept {
            return this->item()->versions();
        }

        /**
         * @copydoc Database::Entry::index(const Database::Version*)
         */
        size_t index(const Database::Version* v) const noexcept{
            return this->get()->index(v);
        }

        inline Version version(size_t index) const noexcept {
            return Version(this->item()->version(index), this->model());
        }

        inline Version latest() const noexcept {
            return Version(this->item()->latest(), this->model());
        }

        inline Version addVersion(Database::Version::Ptr version, size_t index) const{
            return Version(this->model()->addVersion(this->item(), std::move(version), index), this->model());
        }

        inline void removeVersion(size_t index) const{
            this->model()->removeVersion(this->item(), index);
        }

        inline Database::Version::Ptr takeVersion(size_t index) const{
            return this->model()->takeVersion(this->item(), index);
        }

        friend class Group;
        friend class Version;
        friend class DatabaseModel;
    };

    class Version: public Index<Database::Version>{
    private:
        using Index<Database::Version>::Index;

    public:

        /**
         * @copydoc Database::Version::parent()
         *
         * @return Entry index of parent entry.
         */

        inline Entry parent() const noexcept{
            return Entry(this->item()->parent(), this->model());
        }

        inline bool ancestor(const Group& group) const noexcept{
            return parent()->ancestor(group.get());
        }

        /**
         * @copydoc Database::Version::index()
         */
        size_t index() const noexcept{
            return this->get()->index();
        }

        /**
         * @copydoc Database::Version::remove()
         *
         * It renders version index invalid.
         */
        inline void remove() const{
            parent().removeVersion(index());
        }

        friend class Entry;
        friend class DatabaseModel;
    };

    inline DatabaseModel() noexcept
    {}

    inline const Database* get() const noexcept{
        return getDatabase();
    }

    inline const Database* operator->() const noexcept{
        return getDatabase();
    }

    inline Group root() noexcept{
        return Group(getDatabase()->root(), this);
    }

    inline const Database::Group* root() const noexcept{
        return getDatabase()->root();
    }

    /** @brief Returns recycle bin group index or invalid index if no recycle
     *         bin was set.
     *
     * Whether recycle bin is active or not depends not only on a valid group
     * being set, but also on settings().recycleBinEnabled field.
     *
     * Recycle bin group should be used as temporary directory to which
     * deleted groups and entries are moved, and left for some time before
     * being finally deleted. If no recycle bin is set, entries and groups
     * should be deleted immediately.
     */
    inline Group recycleBin() noexcept{
         return Group(getDatabase()->recycleBin(), this);
    }

    inline const Database::Group* recycleBin() const noexcept{
         return getDatabase()->recycleBin();
    }

    /** @brief Sets a new recycle bin group.
     * @param bin New recycle bin Group pointer or nullptr.
     * @param changed Time when recycle bin group was changed. In order to avoid
     *        inconsistencies it is recomended that default value (time()) is used.
     *        Model implementations are allowed to ignore \p changed parameter.
     */
    virtual inline void setRecycleBin(const Database::Group* bin, std::time_t changed = time(nullptr)){
        getDatabase()->setRecycleBin(bin, changed);
    }

    /** @brief Time when recycle bin group was last set (as reported by time()).
     */
    const std::time_t& recycleBinChanged() const noexcept{
        return get()->recycleBinChanged();
    }

    /** @brief Returns templates group index or invalid index if no templates
     *         group was set.
     *
     * Templates group is a special database group. It is recomened to user
     * interface impementers to use entries owned by this group as templates
     * to be presented to the user when creating a new entry.
     */
    inline Group templates() noexcept{
         return Group(getDatabase()->templates(), this);
    }

    inline const Database::Group* templates() const noexcept{
         return getDatabase()->templates();
    }

    /** @brief Sets a templates group.
     * @param templ New templates group index or invalid index.
     * @param changed Time when templates group was changed. In order to avoid
     *        inconsistencies it is recomended that default value (time()) is used.
     *        Model implementations are allowed to ignore \p changed parameter.
     *
     * If \p templ is a valid index, it must point to a group that is owned by
     * this database.
     */
    virtual inline void setTemplates(const Database::Group* templ, std::time_t changed = time(nullptr)){
        getDatabase()->setTemplates(templ, changed);
    }

    /** @brief Time when templates group was last set (as reported by time()).
     */
    const std::time_t& templatesChanged() const noexcept{
        return get()->templatesChanged();
    }

    virtual inline Icon addCustomIcon(CustomIcon::Ptr ptr){
        return getDatabase()->addCustomIcon(std::move(ptr));
    }

    inline Icon addCustomIcon(const Icon& icon){
        if (icon.type() == Icon::Type::Custom)
            return addCustomIcon(icon.custom());
        return icon;
    }

    virtual inline void setProperties(const Database::Group* group, Database::Group::Properties::Ptr properties) {
        const_cast<Database::Group*>(group)->setProperties(std::move(properties));
    }

    virtual inline void setSettings(Database::Settings::Ptr settings) {
        getDatabase()->setSettings(std::move(settings));
    }


    inline Version version(const Database::Version* version) noexcept{
        return Version(const_cast<Database::Version*>(version), this);
    }

    inline Version version(const void* raw) noexcept{
        return version(static_cast<const Database::Version*>(raw));
    }

    inline const Database::Version* version(const void* raw) const noexcept{
        return static_cast<const Database::Version*>(raw);
    }

    inline Entry entry(const Uuid& uuid) noexcept{
        return Entry(getDatabase()->entry(uuid), this);
    }

    inline Entry entry(const Database::Entry* entry) noexcept{
        return Entry(const_cast<Database::Entry*>(entry), this);
    }

    inline Entry entry(const void* raw) noexcept{
        return entry(static_cast<const Database::Entry*>(raw));
    }

    inline const Database::Entry* entry(const void* raw) const noexcept{
        return static_cast<const Database::Entry*>(raw);
    }

    inline Group group(const Uuid& uuid) noexcept{
        return Group(getDatabase()->group(uuid), this);
    }

    inline Group group(const Database::Group* group) noexcept{
        return Group(const_cast<Database::Group*>(group), this);
    }

    inline Group group(const void* raw) noexcept{
        return group(static_cast<const Database::Group*>(raw));
    }

    inline const Database::Group* group(const void* raw) const noexcept{
        return static_cast<const Database::Group*>(raw);
    }

protected:

    virtual Database* getDatabase() const noexcept =0;

    virtual inline Database::Version* addVersion(Database::Entry* entry, Database::Version::Ptr version, size_t index){
        Database::Version* result = version.get();
        entry->addVersion(std::move(version), index, this);
        return result;
    }

    virtual inline void removeVersion(Database::Entry* entry, size_t index){
        entry->removeVersion(index);
    }

    virtual inline Database::Version::Ptr takeVersion(Database::Entry* entry, size_t index) {
        return entry->takeVersion(index);
    }

    virtual inline Database::Entry* addEntry(Database::Group* group, Database::Entry::Ptr entry, size_t index) {
        Database::Entry* result = entry.get();
        group->addEntry(std::move(entry), index, this);
        return result;
    }

    virtual inline void removeEntry(Database::Group* group, size_t index) {
        group->removeEntry(index);
    }

    virtual inline Database::Entry::Ptr takeEntry(Database::Group* group, size_t index) {
        return group->takeEntry(index);
    }

    virtual inline Database::Group* addGroup(Database::Group* parent, Database::Group::Ptr group, size_t index) {
        Database::Group* result = group.get();
        parent->addGroup(std::move(group), index, this);
        return result;
    }

    virtual inline void removeGroup(Database::Group* parent, size_t index) {
        parent->removeGroup(index);
    }

    virtual inline Database::Group::Ptr takeGroup(Database::Group* parent, size_t index) {
        return parent->takeGroup(index);
    }

protected:

    /** @brief Utility function that swaps internal group properties pointer
     *         with \p properties pointer. This method doesn't inform the model
     *         about the change, so it should only be used in reimplementations
     *         of setProperties().
     *
     * @param group Group for which properties should be set.
     * @param properties Reference to a pointer to new properties object. This
     *        pointer is set to point to the old properties object.
     *        This pointer should never be nullptr.
     */
    inline void swapProperties(const Database::Group* group, Database::Group::Properties::Ptr& properties) const{
        properties = const_cast<Database::Group*>(group)->setProperties(std::move(properties));
    }

    /** @brief Utility function that swaps internal database settings pointer
     *         with \p settings pointer. This method doesn't inform the model
     *         about the change, so it should only be used in reimplementations
     *         of setSettings().
     * @param properties Reference to a pointer to new settings object. This
     *        pointer is set to point to the old settings object.
     *        This pointer shuld never be nullptr.
     */
    inline void swapSettings(Database::Settings::Ptr& settings) const{
        settings = getDatabase()->setSettings(std::move(settings));
    }

};

template <typename ModelType>
class DatabaseModelCRTP: public DatabaseModel{
public:

    //static_assert(std::is_base_of<DatabaseModelCRTP<ModelType>, ModelType>::value, "DatabaseModelCRTP must be used as CRTP base class template.");

    class Group;
    class Entry;
    class Version;

    class Group: public DatabaseModel::Group{
    private:

        /** @brief Utility constructor for quick method result transformation.*/
        inline explicit Group(const DatabaseModel::Group& group) noexcept
            :DatabaseModel::Group(group)
        {}

        inline Group(Database::Group* group, ModelType* model) noexcept
            :DatabaseModel::Group(group, model)
        {}

        inline Group(void* raw, ModelType* model) noexcept
            :DatabaseModel::Group(raw, model)
        {}

    public:

        inline Group() noexcept
            :DatabaseModel::Group()
        {}


        Group(const Group& index) = default;
        Group& operator=(const Group& index) = default;

        inline ModelType* model() const noexcept{
            return static_cast<ModelType*>(DatabaseModel::Group::model());
        }

        /**
         * @copydoc Database::Group::parent()
         *
         * @return Group index of parent group.
         */
        inline Group parent() const noexcept{
            return Group(DatabaseModel::Group::parent());
        }

        inline Group group(size_t index) const noexcept{
            return Group(DatabaseModel::Group::group(index));
        }

        inline Entry entry(size_t index) const noexcept{
            return Entry(DatabaseModel::Group::entry(index));
        }

        inline Group addGroup(Database::Group::Ptr group, size_t index) const{
            return Group(DatabaseModel::Group::addGroup(std::move(group), index));
        }

        inline Entry addEntry(Database::Entry::Ptr entry, size_t index) const{
            return Entry(DatabaseModel::Group::addEntry(std::move(entry), index));
        }

        friend class Entry;
        friend class DatabaseModelCRTP;
        friend ModelType;
    };

    class Entry: public DatabaseModel::Entry{
    protected:
        /** @brief Utility constructor for quick method result transformation.*/
        inline explicit Entry(const DatabaseModel::Entry& entry) noexcept
            :DatabaseModel::Entry(entry)
        {}


        inline Entry(Database::Entry* entry, const ModelType* model) noexcept
            :DatabaseModel::Entry(entry, model)
        {}

        inline Entry(void* raw, ModelType* model) noexcept
            :DatabaseModel::Entry(raw, model)
        {}

    public:

        inline Entry() noexcept
            :DatabaseModel::Entry()
        {}


        Entry(const Entry& index) = default;
        Entry& operator=(const Entry& index) = default;

        inline ModelType* model() const noexcept{
            return static_cast<ModelType*>(DatabaseModel::Entry::model());
        }

        /**
         * @copydoc Database::Entry::parent()
         *
         * @return Group index of parent group.
         */
        inline Group parent() const noexcept{
            return Group(DatabaseModel::Entry::parent());
        }

        inline Version version(size_t index) const noexcept {
            return Version(DatabaseModel::Entry::version(index));
        }

        inline Version latest() const noexcept {
            return Version(DatabaseModel::Entry::latest());
        }

        inline Version addVersion(Database::Version::Ptr version, size_t index) const{
            return Version(DatabaseModel::Entry::addVersion(std::move(version), index));
        }

        friend class Group;
        friend class Version;
        friend class DatabaseModelCRTP;
        friend ModelType;
    };

    class Version: public DatabaseModel::Version{
    private:
        /** @brief Utility constructor for quick method result transformation.*/
        inline explicit Version(const DatabaseModel::Version& version) noexcept
            :DatabaseModel::Version(version)
        {}

        inline Version(Database::Version* version, ModelType* model) noexcept
            :DatabaseModel::Version(version, model)
        {}

        inline Version(void* raw, ModelType* model) noexcept
            :DatabaseModel::Version(raw, model)
        {}

    public:

        inline Version() noexcept
            :DatabaseModel::Version()
        {}

        Version(const Version& index) = default;
        Version& operator=(const Version& index) = default;

        inline ModelType* model() const noexcept{
            return static_cast<ModelType*>(DatabaseModel::Version::model());
        }

        /**
         * @copydoc Database::Version::parent()
         *
         * @return Entry index of parent entry.
         */
        inline Entry parent() const noexcept{
            return Entry(DatabaseModel::Version::parent());
        }

        friend class Entry;
        friend class DatabaseModelCRTP;
        friend ModelType;
    };

    using DatabaseModel::DatabaseModel;

    inline Group root() noexcept{
        return Group(DatabaseModel::root());
    }

    inline const Database::Group* root() const noexcept{
        return DatabaseModel::root();
    }

    /** @brief Returns templates group index or invalid index if no templates
     *         group was set.
     *
     * Templates group is a special database group. It is recomened to user
     * interface impementers to use entries owned by this group as templates
     * to be presented to the user when creating a new entry.
     */
    inline Group templates() noexcept{
         return Group(DatabaseModel::templates());
    }

    inline const Database::Group* templates() const noexcept{
         return Group(DatabaseModel::templates());
    }

    /** @brief Returns recycle bin group index or invalid index if no recycle
     *         bin was set.
     *
     * Whether recycle bin is active or not depends not only on a valid group
     * being set, but also on settings().recycleBinEnabled field.
     *
     * Recycle bin group should be used as temporary directory to which
     * deleted groups and entries are moved, and left for some time before
     * being finally deleted. If no recycle bin is set, entries and groups
     * should be deleted immediately.
     */
    inline Group recycleBin() noexcept{
         return Group(DatabaseModel::recycleBin());
    }

    inline const Database::Group* recycleBin() const noexcept{
         return DatabaseModel::recycleBin();
    }

    inline Version version(const Database::Version* v)noexcept{
        return Version(DatabaseModel::version(v));
    }

    inline Version version(const void* raw) noexcept{
        return Version(DatabaseModel::version(raw));
    }

    inline const Database::Version* version(const void* raw) const noexcept{
        return DatabaseModel::version(raw);
    }

    inline Entry entry(const Uuid& uuid) noexcept{
        return Entry(DatabaseModel::entry(uuid));
    }

    inline Entry entry(const Database::Entry* e) noexcept{
        return Entry(DatabaseModel::entry(e));
    }

    inline Entry entry(const void* raw) noexcept{
        return Entry(DatabaseModel::entry(raw));
    }

    inline const Database::Entry* entry(const void* raw) const noexcept{
        return DatabaseModel::entry(raw);
    }

    inline Group group(const Uuid& uuid) noexcept{
        return Group(DatabaseModel::group(uuid));
    }

    inline Group group(const Database::Group* g) noexcept{
        return Group(DatabaseModel::group(g));
    }

    inline Group group(const void* raw) noexcept{
        return Group(DatabaseModel::group(raw));
    }

    inline const Database::Group* group(const void* raw) const noexcept{
        return DatabaseModel::group(raw);
    }

};


}



#endif
