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
#ifndef LIBKEEPASS2PP_ICON_H
#define LIBKEEPASS2PP_ICON_H

#include "platform.h"
#include <memory>

namespace Kdbx {

/** @brief Enumeration defining standard icons that KeePass 2 references by
 *         predefined values/enumerators.
 */
enum class StandardIcon{
        Key = 0,
        World,
        Warning,
        NetworkServer,
        MarkedDirectory,
        UserCommunication,
        Parts,
        Notepad,
        WorldSocket,
        Identity,
        PaperReady,
        Digicam,
        IRCommunication,
        MultiKeys,
        Energy,
        Scanner,
        WorldStar,
        CDRom,
        Monitor,
        EMail,
        Configuration,
        ClipboardReady,
        PaperNew,
        Screen,
        EnergyCareful,
        EMailBox,
        Disk,
        Drive,
        PaperQ,
        TerminalEncrypted,
        Console,
        Printer,
        ProgramIcons,
        Run,
        Settings,
        WorldComputer,
        Archive,
        Homebanking,
        DriveWindows,
        Clock,
        EMailSearch,
        PaperFlag,
        Memory,
        TrashBin,
        Note,
        Expired,
        Info,
        Package,
        Folder,
        FolderOpen,
        FolderPackage,
        LockOpen,
        PaperLocked,
        Checked,
        Pen,
        Thumbnail,
        Book,
        List,
        UserKey,
        Tool,
        Home,
        Star,
        Tux,
        Feather,
        Apple,
        Wiki,
        Money,
        Certificate,
        BlackBerry,

        /// <summary>
        /// Virtual identifier -- represents the number of icons.
        /// </summary>
        Count
};

/** @brief CustomIcon class represents a non-standard icon that can be embedded
 *         in the database.
 *
 * Each custom icon is identified by an UUID, and contains a data buffer that
 * describes icon's content. Currently, KeePass2 seems to use PNG format
 * exclusively when saving database files, but it is unknown what format it is
 * able to process.
 */
class CustomIcon{
public:
    /** @brief Shared pointer to a custom icon object.*/
    typedef std::shared_ptr<const CustomIcon> Ptr;

    /** @brief Constructs a custom icon object with specified UUID and buffer
     *         as it's contents.*/
    inline CustomIcon(Uuid uuid, std::vector<uint8_t> data) noexcept
        :fuuid(std::move(uuid)),
          fdata(std::move(data))
    {}

    CustomIcon(CustomIcon&& icon) = default;
    CustomIcon(const CustomIcon&) = default;
    CustomIcon& operator=(const CustomIcon&) = default;
    CustomIcon& operator=(CustomIcon&&) = default;

    /** @brief Returns CustomIcon's UUID. */
    inline const Uuid& uuid() const noexcept{
        return fuuid;
    }

    /** @brief Returns a reference to CustomIcon's data buffer. */
    inline const std::vector<uint8_t>& data() const noexcept{
        return fdata;
    }

private:
    Uuid fuuid;
    std::vector<uint8_t> fdata;
};

class Icon{
public:
    enum class Type{ Null, Standard, Custom};
private:
    union{
        CustomIcon::Ptr fcustomIcon;
        StandardIcon fstandardIcon;
    };
    Type ftype;

public:

    inline Icon() noexcept
        :ftype(Type::Null)
    {}

    inline explicit Icon(CustomIcon::Ptr icon) noexcept
        :ftype(Type::Custom)
    {
        new (&fcustomIcon) CustomIcon::Ptr(std::move(icon));
    }

    inline explicit Icon(StandardIcon icon) noexcept
        :fstandardIcon(icon),
          ftype(Type::Standard)
    {}

    inline Icon(const Icon& icon) noexcept
        :ftype(icon.ftype)
    {
        switch (ftype){
        case Type::Custom:
            new (&fcustomIcon) CustomIcon::Ptr(icon.fcustomIcon);
            break;
        case Type::Standard:
            fstandardIcon = icon.fstandardIcon;
            break;
        default:
            break;
        }
    }

    inline Icon(Icon&& icon) noexcept
        :ftype(icon.ftype)
    {
        switch (ftype){
        case Type::Custom:
            new (&fcustomIcon) CustomIcon::Ptr(std::move(icon.fcustomIcon));
            break;
        case Type::Standard:
            fstandardIcon = icon.fstandardIcon;
            break;
        default:
            break;
        }
    }

    inline ~Icon() noexcept{
        if (ftype == Type::Custom){
            fcustomIcon.~shared_ptr();
        }
    }

    inline Icon& operator=(const Icon& icon) noexcept{
        if (ftype == Type::Custom){
            fcustomIcon.~shared_ptr();
        }

        ftype = icon.ftype;
        switch (ftype){
        case Type::Custom:
            new (&fcustomIcon) CustomIcon::Ptr(icon.fcustomIcon);
            break;
        case Type::Standard:
            fstandardIcon = icon.fstandardIcon;
            break;
        default:
            break;
        }
        return *this;
    }

    inline Icon& operator=(Icon&& icon) noexcept{
        if (ftype == Type::Custom){
            fcustomIcon.~shared_ptr();
        }

        ftype = icon.ftype;
        switch (ftype){
        case Type::Custom:
            new (&fcustomIcon) CustomIcon::Ptr(std::move(icon.fcustomIcon));
            break;
        case Type::Standard:
            fstandardIcon = icon.fstandardIcon;
            break;
        default:
            break;
        }
        return *this;
    }

    inline Icon& operator=(CustomIcon::Ptr ci) noexcept{
        if (ftype == Type::Custom){
            fcustomIcon = std::move(ci);
        }else{
            ftype = Type::Custom;
            new (&fcustomIcon) CustomIcon::Ptr(std::move(ci));
        }
        return *this;
    }

    inline Icon& operator=(StandardIcon si) noexcept{
        if (ftype == Type::Custom){
            fcustomIcon.~shared_ptr();
        }
        ftype = Type::Standard;
        fstandardIcon = si;
        return *this;
    }

    inline explicit operator bool() const noexcept{
        return ftype != Type::Null;
    }

    inline bool operator!() const noexcept{
        return ftype == Type::Null;
    }

    inline bool operator==(const Icon& icon) const noexcept{
        if (ftype != icon.ftype)
            return false;

        switch (ftype){
        case Type::Custom:
            return fcustomIcon == icon.fcustomIcon ||
                   fcustomIcon->uuid() == icon.fcustomIcon->uuid();
        case Type::Standard:
            return fstandardIcon == icon.fstandardIcon;
        default:
            return true;
        }
    }

    inline bool operator!=(const Icon& icon) const noexcept{
        return !(*this == icon);
    }

    inline Type type() const noexcept{
        return ftype;
    }

    inline const CustomIcon::Ptr& custom() const noexcept{
        return fcustomIcon;
    }

    inline StandardIcon standard() const noexcept{
        return fstandardIcon;
    }

};

}

#endif // LIBKEEPASS2PP_ICON_H
