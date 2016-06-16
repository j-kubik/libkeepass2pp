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

namespace Kdbx{

class CompositeKey{
public:

	class Key{
	public:

		enum class Type{
			Password, KeyFile, Buffer, UserAccount
		};

		Key(std::vector<uint8_t> data, Type type) noexcept
			:fdata(std::move(data)),
			  ftype(type)
		{}

		inline const std::vector<uint8_t>& data() const noexcept{
			return fdata;
		}

		inline Type type() const noexcept{
			return ftype;
		}

		static Key fromPassword(std::string passwd);
		static Key fromFile(std::string filename);

	private:
		std::vector<uint8_t> fdata;
		Type ftype;

	};

	void addKey(Key key){
		keys.push_back(key);
	}

	std::array<uint8_t, 32> getCompositeKey(const std::array<uint8_t, 32>& transformSeed, uint64_t encryptionRounds) const noexcept;

private:

	std::vector<Key> keys;


};

}




#endif // COMPOSITEKEY_H
