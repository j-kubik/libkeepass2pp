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
#include "../include/libkeepass2pp/databasemodel.h"
#include <algorithm>

namespace Kdbx{

//------------------------------------------------------------------------------

//static inline Kdbx::Icon insertIcon(Kdbx::Icon icon, Kdbx::Database* database){
//    if (icon.type() == Icon::Type::Custom){
//        return database->addCustomIcon(icon.custom());
//    }
//    return icon;
//}

//static inline Kdbx::Icon insertIcon(Kdbx::Icon icon, Kdbx::Database* database, DatabaseModel* model){
//    unused(database);
//    if (icon.type() == Icon::Type::Custom){
//        return model->addCustomIcon(icon.custom());
//    }
//    return icon;
//}

static inline void dropGroups(Kdbx::Database::Group* group,
                              Kdbx::Database* database){
    if (database->recycleBin() == group)
        database->setRecycleBin(nullptr);
    if (database->templates() == group)
        database->setTemplates(nullptr);
}

static inline void dropGroups(Kdbx::Database::Group* group,
                              Kdbx::Database* database,
                              DatabaseModel* model){
    if (database->recycleBin() == group)
        model->setRecycleBin(nullptr);
    if (database->templates() == group)
        model->setTemplates(nullptr);
}

//------------------------------------------------------------------------------

void Database::Settings::setName(std::string name) noexcept{
    if (name != fname){
        using std::swap;
        swap(name, fname);
        fnameChanged = time(nullptr);
    }
}

void Database::Settings::setDescription(std::string description) noexcept{
    if (description != fdescription){
        using std::swap;
        swap(description, fdescription);
        fdescriptionChanged = time(nullptr);
    }
}

void Database::Settings::setDefaultUsername(std::string username) noexcept{
    if (username != fdefaultUsername){
        using std::swap;
        swap(username, fdefaultUsername);
        fdefaultUsernameChanged = time(nullptr);
    }
}

//------------------------------------------------------------------------------

template <typename ...Args>
void Database::Version::setDatabase(Args... args){
    Database* db = parent()->parent()->database();
    if (icon.type() == Icon::Type::Custom){
        icon = db->addIcon(icon.custom(), args...);
        db->refIcon(icon.custom());
    }
}

void Database::Version::clearDatabase(){
    if (icon.type() == Icon::Type::Custom){
        parent()->parent()->database()->unrefIcon(icon.custom());
    }
}

size_t Database::Version::index() const noexcept{
    const Entry* p = parent();
    assert(p);
    for (size_t i=0; i<p->versions(); ++i){
        if (p->version(i) == this)
            return i;
    }
    assert("Internal error." == nullptr);
    return -1;
}

//--------------------------------------------------------------------------------------

Database::Entry::Entry(const Entry& entry)
    :fuuid(Uuid::generate()),
      fparent(nullptr)
{
    fversions.reserve(entry.fversions.size());
    for (const Version::Ptr& version: entry.fversions){
        Version* v = new Version(*version);
        v->fparent = this;
        fversions.emplace_back(v);
    }
}

void Database::Entry::addVersion(Version::Ptr version, size_t index){
    Version* tmp = version.get();
    version->fparent = this;
    fversions.insert(fversions.begin()+index, std::move(version));
    if (fparent && fparent->database())
        tmp->setDatabase();
}

void Database::Entry::addVersion(Version::Ptr version, size_t index, DatabaseModel* model){
    Version* tmp = version.get();
    version->fparent = this;
    fversions.insert(fversions.begin()+index, std::move(version));
    tmp->setDatabase(model);
}

Database::Version::Ptr Database::Entry::takeVersion(size_t index) noexcept{
    assert(fversions.size() > 1);

    if (fparent && fparent->database())
        fversions[index].get()->clearDatabase();

    Version::Ptr result = std::move(fversions[index]);
    fversions.erase(fversions.begin() + index);
    result->fparent = 0;
    return result;
}

template <typename ...Args>
void Database::Entry::setDatabase(Args... args){
    Database* db = parent()->database();

    auto del = db->fdeletedObjects.find(fuuid);
    if (del != db->fdeletedObjects.end()){
        db->fdeletedObjects.erase(del);
    }

    for (const Version::Ptr& v: fversions){
        v->setDatabase(args...);
    }

}

void Database::Entry::clearDatabase(){
    for (const Version::Ptr& v: fversions){
        v->clearDatabase();
    }
    fparent->fdatabase->fdeletedObjects[fuuid] = time(nullptr);
}

//-----------------------------------------------------------------------------------

Database::Group::Group(const Group& group)
    :fparent(nullptr),
      fdatabase(nullptr),
      fuuid(Uuid::generate()),
      fproperties(new Properties(*group.fproperties))
{
    fentries.reserve(group.fentries.size());
    for (const Entry::Ptr& entry: group.fentries){
        Entry* e = new Entry(*entry);
        e->fparent = this;
        fentries.emplace_back(e);
    }

    fgroups.reserve(group.fgroups.size());
    for (const Group::Ptr& gr: group.fgroups){
        Group* g = new Group(*gr);
        g->fparent = this;
        g->fdatabase = nullptr;
        fgroups.emplace_back(g);
    }
}

Database::Group::Properties::Ptr Database::Group::setProperties(Properties::Ptr properties){

    if (fdatabase){
        if (properties->icon.type() == Icon::Type::Custom){
            properties->icon = fdatabase->addIcon(properties->icon.custom());
            fdatabase->refIcon(properties->icon.custom());
        }
        if (fproperties->icon.type() == Icon::Type::Custom){
            fdatabase->unrefIcon(fproperties->icon.custom());
        }
    }

    using std::swap;
    swap(fproperties, properties);
    return properties;
}

bool Database::Group::ancestor(const Group* group) const noexcept{
    const Group* g = this;
    while (g){
        if (g == group)
            return true;
        g = g->parent();
    }
    return false;
}

size_t Database::Group::index(const Group* g) const noexcept{
    for (size_t i=0; i<groups(); ++i){
        if (group(i) == g)
            return i;
    }
    assert("Subgroup not present." == nullptr);
    return 0;
}

size_t Database::Group::index(const Entry* e) const noexcept{
    for (size_t i=0; i<entries(); ++i){
        if (entry(i) == e)
            return i;
    }
    assert("Entry not present." == nullptr);
    return 0;
}

void Database::Group::addGroup(Group::Ptr group, size_t index){
    assert(index <= groups());
    assert(group->fparent == nullptr);

    group->fparent = this;
    fgroups.insert(fgroups.begin()+index, std::move(group));

    if (fdatabase)
        fgroups[index]->setDatabase();
}

Database::Group::Ptr Database::Group::takeGroup(size_t index) noexcept{
    assert(index < groups());
    if (fdatabase)
        fgroups[index]->clearDatabase();

    Group::Ptr result(std::move(fgroups[index]));
    fgroups.erase(fgroups.begin()+index);
    result->fparent = nullptr;
    return result;
}

void Database::Group::moveGroup(size_t index, Group* newParent, size_t newIndex){
    assert(index < groups());
    assert(newParent != nullptr);
    assert(fdatabase == newParent->fdatabase);
    assert(newParent->ancestor(group(index)) == false && newParent != group(index));
    assert(newIndex <= newParent->groups());
    assert(this != newParent || (newIndex != index && newIndex != index+1));

    Group::Ptr group(std::move(fgroups.at(index)));
    fgroups.erase(fgroups.begin()+index);

    if (newParent == this && newIndex > index)
        newIndex--;

    group->fparent = newParent;
    newParent->fgroups.insert(newParent->fgroups.begin()+newIndex, std::move(group));
}

void Database::Group::addEntry(Entry::Ptr entry, size_t index){
    entry->fparent = this;
    fentries.insert(fentries.begin()+index, std::move(entry));
    if (fdatabase)
        fentries[index]->setDatabase();
}

Database::Entry::Ptr Database::Group::takeEntry(size_t index) noexcept{

    if (fdatabase)
        fentries[index]->clearDatabase();
    Entry::Ptr result(std::move(fentries[index]));
    fentries.erase(fentries.begin()+ index);
    result->fparent = nullptr;
    return result;
}

void Database::Group::moveEntry(size_t index, Group* newParent, size_t newIndex){
    assert(index < entries());
    assert(newParent != nullptr);
    assert(fdatabase == newParent->fdatabase);
    assert(newIndex <= newParent->entries());
    assert(this != newParent || (newIndex != index && newIndex != index+1));

    Entry::Ptr entry(std::move(fentries.at(index)));
    fentries.erase(fentries.begin()+index);

    if (newParent == this && newIndex > index)
        newIndex--;

    entry->fparent = newParent;
    newParent->fentries.insert(newParent->fentries.begin()+newIndex, std::move(entry));
}

template <typename ...Args>
void Database::Group::setDatabase(Args... args){
    assert(fdatabase == nullptr);
    assert(fparent != nullptr);
    assert(fparent->fdatabase != nullptr);
    fdatabase = fparent->fdatabase;

    auto del = fdatabase->fdeletedObjects.find(fuuid);
    if (del != fdatabase->fdeletedObjects.end()){
        fdatabase->fdeletedObjects.erase(del);
    }

    if (fproperties->icon.type() == Icon::Type::Custom){
        fproperties->icon = fdatabase->addIcon(fproperties->icon.custom(), args...);
        fdatabase->refIcon(fproperties->icon.custom());
    }

    for (const Entry::Ptr& entry: fentries){
        entry->setDatabase(args...);
    }

    for (const Group::Ptr& group: fgroups){
        group->setDatabase(args...);
    }
}

template <typename ...Args>
void Database::Group::clearDatabase(Args... args) noexcept{
    assert(fdatabase != nullptr);

    for (const Entry::Ptr& entry: fentries)
        entry->clearDatabase();

    for (const Group::Ptr& group: fgroups)
        group->clearDatabase(args...);

    dropGroups(this, fdatabase, args...);

    if (fproperties->icon.type() == Icon::Type::Custom){
        fdatabase->unrefIcon(fproperties->icon.custom());
    }
    fdatabase->fdeletedObjects[fuuid] = time(nullptr);
    fdatabase = nullptr;
}



Database::Group* Database::Group::groupLookup(const Uuid& uuid) const noexcept{
    for (const Ptr& group: fgroups){
        if (group->fuuid == uuid)
            return group.get();
        Database::Group* result = group->groupLookup(uuid);
        if (result)
            return result;
    }
    return nullptr;
}

Database::Entry* Database::Group::entryLookup(const Uuid& uuid) const noexcept{
    for (const Entry::Ptr& entry: fentries){
        if (entry->uuid() == uuid)
            return entry.get();
    }

    for (const Ptr& group: fgroups){
        Database::Entry* result = group->entryLookup(uuid);
        if (result)
            return result;
    }
    return nullptr;
}

void Database::Group::addGroup(Group::Ptr group, size_t index, DatabaseModel* model){
    assert(index <= groups());
    assert(group->fparent == nullptr);

    Group* tmp = group.get();
    group->fparent = this;
    fgroups.insert(fgroups.begin()+index, std::move(group));
    tmp->setDatabase(model);
}

Database::Group::Ptr Database::Group::takeGroup(size_t index, DatabaseModel* model){
    assert(index < groups());

    fgroups[index]->clearDatabase(model);
    Group::Ptr result(std::move(fgroups[index]));
    fgroups.erase(fgroups.begin()+index);
    result->fparent = nullptr;
    return result;
}

void Database::Group::addEntry(Entry::Ptr entry, size_t index, DatabaseModel* model){
    assert(index <= entries());
    assert(entry->fparent == nullptr);
    Entry* tmp = entry.get();
    entry->fparent = this;
    fentries.insert(fentries.begin()+index, std::move(entry));
    tmp->setDatabase(model);
}


Database::Group::Properties::Ptr Database::Group::setProperties(Properties::Ptr properties, DatabaseModel* model){

    if (fdatabase){
        if (properties->icon.type() == Icon::Type::Custom){
            properties->icon = model->addIcon(properties->icon.custom());
            fdatabase->refIcon(properties->icon.custom());
        }
        if (fproperties->icon.type() == Icon::Type::Custom){
            fdatabase->unrefIcon(fproperties->icon.custom());
        }
    }

    using std::swap;
    swap(fproperties, properties);
    return properties;
}



//-------------------------------------------------------------------------------------

Database::Database(CompositeKey key)
    :froot(new Group(this)),
      fsettings(new Settings()),
      fcompositeKey(std::move(key)),
      frecycleBin(nullptr),
      ftemplates(nullptr)
{
    std::time_t currentTime=time(nullptr);
    fsettings->fnameChanged = currentTime;
    fsettings->fdescriptionChanged = currentTime;
    fsettings->fdefaultUsernameChanged = currentTime;
    frecycleBinChanged = currentTime;
    ftemplatesChanged = currentTime;
    fcompositeKeyChanged = currentTime;
}

void Database::setRecycleBin(const Group* bin, std::time_t changed) noexcept{
    assert(!bin || bin->database() == this);
    if (frecycleBin != bin){
        frecycleBin = const_cast<Group*>(bin);
        frecycleBinChanged = changed;
    }
}

void Database::setTemplates(const Group* templ, std::time_t changed) noexcept{
    assert(!templ || templ->database() == this);
    if (ftemplates != templ){
        ftemplates = const_cast<Group*>(templ);
        ftemplatesChanged = changed;
    }
}

CompositeKey Database::setCompositeKey(CompositeKey key, std::time_t changed) noexcept{
    using std::swap;
    swap(fcompositeKey, key);
    fcompositeKeyChanged = changed;
    return std::move(key);
}

//------ Custom icons functions ------


CustomIcon::Ptr Database::icon(const Uuid& uuid) const noexcept{
    int index = iconIndex(uuid);
    if (index < 0)
        return nullptr;
    return fcustomIcons[index].first;
}

int Database::iconIndex(const Uuid& uuid) const noexcept{
    for (size_t i=0; i<fcustomIcons.size(); ++i){
        if (fcustomIcons[i].first->uuid() == uuid)
            return i;
    }
    return -1;
}

int Database::iconIndex(const CustomIcon::Ptr& icon) const noexcept{
    for (size_t i=0; i<fcustomIcons.size(); ++i){
        if (fcustomIcons[i].first == icon ||
            fcustomIcons[i].first->uuid() == icon->uuid())
            return i;
    }
    return -1;
}

Icon Database::addIcon(CustomIcon::Ptr icon){
    int index = iconIndex(icon);
    if (index < 0){
        insertIcon(icon);
        return Icon(std::move(icon));
    }
    return Icon(fcustomIcons[index].first);
}

Icon Database::addIcon(const Icon& icon){
    if (icon.type() == Icon::Type::Custom)
        return addIcon(icon.custom());
    return icon;
}

bool Database::removeIcon(size_t index){
    if (fcustomIcons[index].second == 0){
        eraseIcon(index);
        return true;
    }
    return false;
}

bool Database::removeIcon(const CustomIcon::Ptr& icon){
    int index = iconIndex(icon);
    if (index < 0)
        return false;
    return removeIcon(index);
}

bool Database::removeIcon(const Icon& icon){
    if (icon.type() == Icon::Type::Custom)
        return removeIcon(icon.custom());
    return false;
}

Icon Database::icon(const Uuid& cicon, StandardIcon sicon) const noexcept{
    if (cicon){
        int index = iconIndex(cicon);
        if (index >= 0)
            return Icon(icon(index));
    }
    return Icon(sicon);
}

Icon Database::addIcon(CustomIcon::Ptr icon, DatabaseModel* model){
    int index = iconIndex(icon);
    if (index < 0){
        model->insertIcon(icon);
        return Icon(std::move(icon));
    }
    return Icon(fcustomIcons[index].first);
}

bool Database::removeIcon(size_t index, DatabaseModel* model){
    if (fcustomIcons[index].second == 0)
        return false;
    model->eraseIcon(index);
    return true;
}

void Database::insertIcon(CustomIcon::Ptr icon){
    assert(iconIndex(icon) < 0);
    fcustomIcons.emplace_back(std::pair<CustomIcon::Ptr, size_t>(icon, 0));
}

void Database::eraseIcon(size_t index){
    assert(index < fcustomIcons.size());
    assert(fcustomIcons[index].second == 0);
    fcustomIcons.erase(fcustomIcons.begin()+index);
}

void Database::refIcon(const CustomIcon::Ptr& icon){
    int index = iconIndex(icon);
    assert(index >= 0);
    fcustomIcons[index].second++;
}

void Database::unrefIcon(const CustomIcon::Ptr& icon){
    int index = iconIndex(icon);
    assert(index >= 0);
    fcustomIcons[index].second--;
}

//-------------------------------------------------------------------------------------

void DatabaseModel::insertIcon(CustomIcon::Ptr icon){
    getDatabase()->insertIcon(std::move(icon));
}

void DatabaseModel::eraseIcon(size_t index){
    getDatabase()->eraseIcon(index);
}

}






