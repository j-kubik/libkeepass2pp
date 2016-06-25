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
class BasicDatabaseModel{
private:
    Database::Ptr fdatabase;

public:

    inline BasicDatabaseModel() noexcept
    {}

    inline BasicDatabaseModel(Database::Ptr database) noexcept
        :fdatabase(std::move(database))
    {}


    inline const Database* get() const noexcept{
        return fdatabase.get();
    }

    inline const Database* operator->() const noexcept{
        return fdatabase.get();
    }

    inline BasicDatabaseModel& operator=(Database::Ptr database) noexcept{
        reset(std::move(database));
        return *this;
    }

    /** Changes the database that a model uses.
     *
     * It invalidates all database indexes belonging to the model.
     */
    virtual inline Database::Ptr reset(Database::Ptr newDatabase){
        using std::swap;
        swap(fdatabase, newDatabase);
        return std::move(newDatabase);
    }

    virtual inline Icon addCustomIcon(CustomIcon::Ptr ptr){
        return fdatabase->addCustomIcon(std::move(ptr));
    }

    inline Icon addCustomIcon(const Icon& icon){
        if (icon.type() == Icon::Type::Custom)
            return addCustomIcon(icon.custom());
        return icon;
    }

protected:

    virtual inline Database::Version* addVersion(Database::Entry* entry, Database::Version::Ptr version, size_t index){
        Database::Version* result = version.get();
        entry->addVersion(std::move(version), index, this);
        return result;
    }

    virtual inline void removeVersion(Database::Entry* entry, size_t index){
        entry->removeVersion(index);
    }

    virtual inline Database::Version::Ptr takeVersion(Database::Entry* entry, size_t index){
        return entry->takeVersion(index);
    }

    virtual inline Database::Entry* addEntry(Database::Group* group, Database::Entry::Ptr entry, size_t index){
        Database::Entry* result = entry.get();
        group->addEntry(std::move(entry), index, this);
        return result;
    }

    virtual inline void removeEntry(Database::Group* group, size_t index){
        group->removeEntry(index);
    }

    virtual inline Database::Entry::Ptr takeEntry(Database::Group* group, size_t index){
        return group->takeEntry(index);
    }

    virtual inline Database::Group* addGroup(Database::Group* parent, Database::Group::Ptr group, size_t index){
        Database::Group* result = group.get();
        parent->addGroup(std::move(group), index, this);
        return result;
    }

    virtual inline void removeGroup(Database::Group* parent, size_t index){
        parent->removeGroup(index);
    }

    virtual inline Database::Group::Ptr takeGroup(Database::Group* parent, size_t index){
        return parent->takeGroup(index);
    }

    virtual inline void setProperties(Database::Group* group, Database::Group::Properties::Ptr properties){
        group->setProperties(std::move(properties));
    }

    virtual inline void setSettings(Database::Settings::Ptr settings){
        fdatabase->setSettings(std::move(settings));
    }

    /** @brief Utility function that swaps internal group properties pointer with \p
     *         properties pointer.
     * @param group Group for which properties should be set.
     * @param properties Reference to a pointer to new properties object. This pointer
     *        is set to point to the old properties object.
     *        This pointer should never be nullptr.
     */
    inline void swapProperties(Database::Group* group, Database::Group::Properties::Ptr& properties){
        properties = group->setProperties(std::move(properties));
    }

    /** @brief Utility function that swaps internal database settings pointer with \p
     *         settings pointer.
     * @param properties Reference to a pointer to new settings object. This pointer
     *        is set to point to the old settings object.
     *        This pointer shuld never be nullptr.
     */
    inline void swapSettings(Database::Settings::Ptr& settings){
        settings = fdatabase->setSettings(std::move(settings));
    }

    template <typename ModelType>
    friend class DatabaseModel;
};

template <typename ModelType>
class DatabaseModel: public BasicDatabaseModel{
public:

    template <typename ItemType>
    class Index{
    private:
        ItemType* fitem;
        ModelType* fmodel;

    protected:

        inline Index(ItemType* group, ModelType* model) noexcept
            :fitem(group),
              fmodel(model)
        {}

        inline ItemType* item() const noexcept{
            return fitem;
        }

    public:

        inline const ItemType* get() const noexcept{
            return fitem;
        }

        inline Index() noexcept
            :fitem(nullptr),
              fmodel(nullptr)
        {}

        template <typename OtherIndexType, typename = typename std::enable_if<std::is_convertible<decltype(std::declval<OtherIndexType>().model()), ModelType*>::value &&
                                                                              std::is_same<decltype(std::declval<Index>().get()), decltype(std::declval<OtherIndexType>().get())>::value>::type>
        inline Index(const OtherIndexType& index) noexcept
            :fitem(index.fitem),
              fmodel(index.fmodel)
        {}

        inline Index(void* raw, ModelType* model) noexcept
            :fitem(reinterpret_cast<ItemType*>(raw)),
              fmodel(model)
        {}

        inline ModelType* model() const noexcept{
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

        template <typename OtherItemType>
        friend class Index;
        friend class DatabaseModel<typename std::remove_const<ModelType>::type>;
        friend class DatabaseModel<const ModelType>;

    };

    class Entry;
    class Version;

    class Group: public Index<Database::Group>{
    private:
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
            DatabaseModel* model = this->model();
            model->setProperties(this->item(), std::move(properties));
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
            assert(parent());
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
            DatabaseModel* model = this->model();
            return Group(model->addGroup(this->item(), std::move(group), index), this->model());
        }

        inline Entry addEntry(Database::Entry::Ptr entry, size_t index) const{
            DatabaseModel* model = this->model();
            return Entry(model->addEntry(this->item(), std::move(entry), index), this->model());
        }

        inline void removeGroup(size_t index) const{
            DatabaseModel* model = this->model();
            model->removeGroup(this->item(), index);
        }

        inline void removeEntry(size_t index) const{
            DatabaseModel* model = this->model();
            model->removeEntry(this->item(), index);
        }

        friend class Entry;
        friend class DatabaseModel<typename std::remove_const<ModelType>::type>;
        friend class DatabaseModel<const ModelType>;
        friend ModelType;
    };

    class Entry: public Index<Database::Entry>{
    private:
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
            DatabaseModel* model = this->model();
            return Version(model->addVersion(this->item(), std::move(version), index), this->model());
        }

        inline void removeVersion(size_t index) const{
            DatabaseModel* model = this->model();
            model->removeVersion(this->item(), index);
        }

        inline Database::Version::Ptr takeVersion(size_t index) const{
            DatabaseModel* model = this->model();
            return model->takeVersion(this->item(), index);
        }

        friend class Group;
        friend class Version;
        friend class DatabaseModel<typename std::remove_const<ModelType>::type>;
        friend class DatabaseModel<const ModelType>;
        friend ModelType;
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

        // ToDo: SFINAE
        template <typename AnotherGroupType>
        inline bool ancestor(const AnotherGroupType& group) const noexcept{
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
        friend class DatabaseModel<typename std::remove_const<ModelType>::type>;
        friend class DatabaseModel<const ModelType>;
        friend ModelType;
    };

    using BasicDatabaseModel::BasicDatabaseModel;
    using BasicDatabaseModel::operator=;

    inline DatabaseModel(Database::Ptr database) noexcept
        :BasicDatabaseModel(std::move(database))
    {}

    inline Group root() noexcept{
        return Group(fdatabase->root(), static_cast<ModelType*>(this));
    }

    inline typename DatabaseModel<const ModelType>::Group root() const noexcept{
        return typename DatabaseModel<const ModelType>::Group(fdatabase->root(), static_cast<const ModelType*>(this));
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
         return Group(fdatabase->recycleBin(), static_cast<ModelType*>(this));
    }

    /** @brief Sets a new recycle bin group.
     * @param bin New recycle bin Group index or invalid index.
     * @param changed Time when recycle bin group was changed. In order to avoid
     *        inconsistencies it is recomended that default value (time()) is used.
     *        Model implementations are allowed to ignore \p changed parameter.
     */
    virtual inline void setRecycleBin(Group bin, std::time_t changed = time(nullptr)){
        fdatabase->setRecycleBin(bin.item(), changed);
    }

    /** @brief Time when recycle bin group was last set (as reported by time()).
     */
    const std::time_t& recycleBinChanged() noexcept{
        return fdatabase->recycleBinChanged();
    }

    /** @brief Returns templates group index or invalid index if no templates
     *         group was set.
     *
     * Templates group is a special database group. It is recomened to user
     * interface impementers to use entries owned by this group as templates
     * to be presented to the user when creating a new entry.
     */
    inline Group templates() noexcept{
         return Group(fdatabase->templates(), static_cast<ModelType*>(this));
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
    virtual inline void setTemplates(Group templ, std::time_t changed = time(nullptr)){
        fdatabase->setTemplates(templ.item(), changed);
    }

    /** @brief Time when templates group was last set (as reported by time()).
     */
    const std::time_t& templatesChanged() noexcept{
        return fdatabase->templatesChanged();
    }

    inline Version version(const Database::Version* version) noexcept{
        return Version(const_cast<Database::Version*>(version), static_cast<ModelType*>(this));
    }

    inline typename DatabaseModel<const ModelType>::Version version(const Database::Version* version) const noexcept{
        return typename DatabaseModel<const ModelType>::Version(const_cast<Database::Version*>(version), static_cast<const ModelType*>(this));
    }

    inline Entry entry(const Uuid& uuid) noexcept{
        return Entry(fdatabase->entry(uuid), static_cast<ModelType*>(this));
    }

    inline typename DatabaseModel<const ModelType>::Entry entry(const Uuid& uuid) const noexcept{
        return typename DatabaseModel<const ModelType>::Entry(fdatabase->entry(uuid), static_cast<ModelType*>(this));
    }

    inline Entry entry(const Database::Entry* entry) noexcept{
        return Entry(const_cast<Database::Entry*>(entry), static_cast<ModelType*>(this));
    }

    inline typename DatabaseModel<const ModelType>::Entry entry(const Database::Entry* entry) const noexcept{
        return typename DatabaseModel<const ModelType>::Entry(const_cast<Database::Entry*>(entry), static_cast<const ModelType*>(this));
    }

    inline Group group(const Uuid& uuid) noexcept{
        return Group(fdatabase->group(uuid), static_cast<ModelType*>(this));
    }

    inline typename DatabaseModel<const ModelType>::Group group(const Uuid& uuid) const noexcept{
        return typename DatabaseModel<const ModelType>::Group(fdatabase->group(uuid), static_cast<ModelType*>(this));
    }

    inline Group group(const Database::Group* group) noexcept{
        return Group(const_cast<Database::Group*>(group), static_cast<ModelType*>(this));
    }

    inline typename DatabaseModel<const ModelType>::Group group(const Database::Group* group) const noexcept{
        return typename DatabaseModel<const ModelType>::Group(const_cast<Database::Group*>(group), static_cast<const ModelType*>(this));
    }


};


}



#endif
