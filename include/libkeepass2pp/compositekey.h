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
#ifndef COMPOSITEKEY_H
#define COMPOSITEKEY_H

#include <vector>
#include <cstdint>
#include <string>
#include <memory>

#include "util.h"

namespace Kdbx{

/**
 * @brief The CompositeKey class represents a key that is composed of several components.
 *
 * Those components can be:
 *  - a password;
 *  - a key file;
 *  - Windows user account (on windows platforms) - currently unsupported.
 *
 * Separate keys are added to the composite key. They are combined when requested using
 *  getCompositeKey method.
 *
 * @note Databases that use windows user account based key as a part of composite key
 *       are tied to specific windows user account. Those databases are inherently
 *       inaccesible on other platforms, and are therefore unsupported. Support may
 *       be added in some futre version of libkeepass2pp.
 */

//ToDo: use safe vectors here!!!
class CompositeKey{
public:

    class Key{
    public:
        typedef std::unique_ptr<Key> Ptr;

        /** @brief Type of singular key.
         *
         * Currentl libkeepass2pp supports only Password and KeyFile
         * composed keys.
         */
        enum class Type{
            Password, //! Password based key;
            KeyFile, //! Key read from key-file;
            Buffer, //! Application provided key of unknown origin;
            UserAccount //! Windows user account - currently unused by libkeepass2pp.
        };

        virtual ~Key() noexcept;

        /** @brief Returns a vector of bytes that represenst a key. */
        virtual SafeVector<uint8_t> data() const = 0;

        /** @brief Returns type of a key.
         *
         * Key type indicates it's origin.
         */
        inline Type type() const noexcept{
            return ftype;
        }

        /** @brief Creates singular key from a password.*/
        static Key::Ptr fromPassword(SafeString<char> passwd);

        /** @brief Creates singlular key read from a key file.
         *
         * Unlike creating key from password, this function can block.
         */
        static Key::Ptr fromFile(SafeString<char> filename);

        /** @brief Creates application-provided buffer key.
         * @param data Key's binary representation.
         */
        static Key::Ptr fromBuffer(SafeVector<uint8_t> data);

    protected:
        /** @brief creates a key out of binary data.
         * @param data Data to use as key's binary representation.
         * @param type Type of key to create.
         */
        Key(Type type) noexcept
            :ftype(type)
        {}

    private:
        Type ftype;

    };

    /** @brief Adds a singular key into composed key set.
     *
     * Order in which keys are added to composite key set is important.
     * Current KeePass 2 GUI uses up to three keys in following order:
     *  - password based key (if provided),
     *  - key-file based key (if provided),
     *  - windows-account based key (if supported and provided).
     */
    void addKey(Key::Ptr key){
        keys.push_back(std::move(key));
    }

    /** @brief Creates a composite key buffer form a set of singualr keys added
     *         to composite key.
     *
     * Calls to this method and addKey() can be intermixed in any order.
     */
    SafeVector<uint8_t> getCompositeKey(const std::array<uint8_t, 32>& transformSeed,
                                        uint64_t encryptionRounds) const;

private:

    std::vector<Key::Ptr> keys;
};

}




#endif // COMPOSITEKEY_H
