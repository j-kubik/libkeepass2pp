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

static inline Kdbx::Icon insertIcon(Kdbx::Icon icon, Kdbx::Database* database){
    if (icon.type() == Icon::Type::Custom){
        return database->addCustomIcon(icon.custom());
    }
    return icon;
}

static inline Kdbx::Icon insertIcon(Kdbx::Icon icon, Kdbx::Database* database, DatabaseModel* model){
    unused(database);
    if (icon.type() == Icon::Type::Custom){
        return model->addCustomIcon(icon.custom());
    }
    return icon;
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
void Database::Version::setDatabase(Database* database, Args... args){
    icon = insertIcon(icon, database, args...);
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
    version->fparent = this;

    if (parent() && parent()->fdatabase)
        version->setDatabase(parent()->fdatabase);
    fversions.insert(fversions.begin()+index, std::move(version));
}

void Database::Entry::addVersion(Version::Ptr version, size_t index, DatabaseModel* model){
    version->fparent = this;
    version->setDatabase(fparent->fdatabase, model);

    fversions.insert(fversions.begin()+index, std::move(version));
}

Database::Version::Ptr Database::Entry::takeVersion(size_t index) noexcept{
    assert(fversions.size() > 1);
    Version::Ptr result = std::move(fversions.at(index));
    fversions.erase(fversions.begin() + index);
    result->fparent = 0;
    return result;
}

void Database::Entry::clearDatabase(){
    fparent->fdatabase->fdeletedObjects[fuuid] = time(nullptr);
}

template <typename ...Args>
void Database::Entry::setDatabase(Database* database, Args... args){

    auto del = database->fdeletedObjects.find(fuuid);
    if (del != database->fdeletedObjects.end()){
        database->fdeletedObjects.erase(del);
    }

    for (const Version::Ptr& version: fversions){
        version->setDatabase(database, args...);
    }

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

bool Database::Group::ancestor(const Group* group) const noexcept{
    const Group* g = parent();
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
    if (fdatabase)
        group->setDatabase(fdatabase);
    fgroups.insert(fgroups.begin()+index, std::move(group));
}

Database::Group::Ptr Database::Group::takeGroup(size_t index) noexcept{
    assert(index < groups());

    Group::Ptr result(std::move(fgroups.at(index)));
    fgroups.erase(fgroups.begin()+index);
    result->fparent = nullptr;
    result->clearDatabase();
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
    if (fdatabase)
        entry->setDatabase(fdatabase);
    fentries.insert(fentries.begin()+index, std::move(entry));
}

Database::Entry::Ptr Database::Group::takeEntry(size_t index) noexcept{
    Entry::Ptr result(std::move(fentries.at(index)));
    fentries.erase(fentries.begin()+ index);
    result->fparent = nullptr;
    if (fdatabase)
        result->clearDatabase();

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

void Database::Group::clearDatabase() noexcept{
    assert(fdatabase != nullptr);

    for (const Entry::Ptr& entry: fentries)
        entry->clearDatabase();

    for (const Group::Ptr& group: fgroups)
        group->clearDatabase();

    if (fdatabase->recycleBin() == this)
        fdatabase->setRecycleBin(nullptr);
    if (fdatabase->templates() == this)
        fdatabase->setTemplates(nullptr);

    fdatabase->fdeletedObjects[fuuid] = time(nullptr);
    fdatabase = nullptr;
}

template <typename ...Args>
void Database::Group::setDatabase(Database* database, Args... args){
    assert(fdatabase == nullptr);
    fdatabase = database;

    auto del = database->fdeletedObjects.find(fuuid);
    if (del != database->fdeletedObjects.end()){
        database->fdeletedObjects.erase(del);
    }

    fproperties->icon = insertIcon(fproperties->icon, database, args...);

    for (const Entry::Ptr& entry: fentries){
        entry->setDatabase(database, args...);
    }

    for (const Group::Ptr& group: fgroups){
        group->setDatabase(database, args...);
    }
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
    group->fparent = this;
    group->setDatabase(fdatabase, model);
    fgroups.insert(fgroups.begin()+index, std::move(group));
}

void Database::Group::addEntry(Entry::Ptr entry, size_t index, DatabaseModel* model){
    assert(index <= entries());
    assert(entry->fparent == nullptr);
    entry->fparent = this;
    fentries.insert(fentries.begin()+index, std::move(entry));
    entry->setDatabase(fdatabase, model);
}

//-------------------------------------------------------------------------------------

Database::Database()
    :froot(new Group(this)),
      fsettings(new Settings()),
      frecycleBin(nullptr),
      ftemplates(nullptr)
{
    std::time_t currentTime=time(nullptr);
    fsettings->fnameChanged = currentTime;
    fsettings->fdescriptionChanged = currentTime;
    fsettings->fdefaultUsernameChanged = currentTime;
    fsettings->masterKeyChanged = currentTime;
    frecycleBinChanged = currentTime;
    ftemplatesChanged = currentTime;
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

int Database::customIconIndex(const Uuid& uuid) const noexcept{
    for (unsigned int i=0; i<fcustomIcons.size(); ++i){
        if (fcustomIcons.at(i)->uuid() == uuid){
            return i;
        }
    }
    return -1;
}

Icon Database::icon(Uuid cicon, StandardIcon sicon) const noexcept{
    if (cicon){
        int index = customIconIndex(std::move(cicon));
        if (index >= 0)
            return Icon(customIcon(index));
    }
    return Icon(sicon);
}

Icon Database::addCustomIcon(CustomIcon::Ptr icon){
    for (const CustomIcon::Ptr& i: fcustomIcons) {
        if (i == icon || i->uuid() == icon->uuid())
            return Icon(i);
    }
    fcustomIcons.push_back(icon);
    return Icon(std::move(icon));
}

//-------------------------------------------------------------------------------------

}






