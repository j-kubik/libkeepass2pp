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
#include <bitset>
#include <functional>
#include <utility>

#include <openssl/sha.h>
#include <openssl/evp.h>

#include "../include/libkeepass2pp/database.h"
#include "../include/libkeepass2pp/compositekey.h"
#include "../include/libkeepass2pp/links.h"
#include "../include/libkeepass2pp/util.h"
#include "../include/libkeepass2pp/cryptorandom.h"

namespace Kdbx{

const std::array<uint8_t, 16> Database::File::AES_CBC_256_UUID = {0x31, 0xC1, 0xF2, 0xE6, 0xBF, 0x71, 0x43, 0x50,
                                                                  0xBE, 0x58, 0x05, 0x21, 0x6A, 0xFC, 0x5A, 0xFF };


const char* const Database::Version::titleString = "Title";
const char* const Database::Version::userNameString = "UserName";
const char* const Database::Version::passwordString = "Password";
const char* const Database::Version::urlString = "URL";
const char* const Database::Version::notesString = "Notes";

//------------------------------------------------------------------------------

struct Database::Meta{
public:
    class Binary;
    class Binaries;

    inline Meta()
        :settings(new Database::Settings())
    {}

    inline Meta(const Database::File::Settings& settings)
        :settings(new Database::Settings(settings))
    {}

    Database::Settings::Ptr settings;
    Uuid recycleBinUUID;
    Uuid templatesUUID;
    std::time_t recycleBinChanged;
    std::time_t templatesChanged;
    std::array<uint8_t, 32> headerHash; // ToDo: make use of this field...
    CustomIcons customIcons;
    std::map<std::string, std::string> customData;
    std::map<std::string, std::shared_ptr<SafeVector<uint8_t>>> binaries;
};

class Database::Version::Binary{
public:
    class Value;
};

namespace Internal{

//struct Header{
//    uint8_t sig1[sizeof(uint32_t)];
//    uint8_t sig2[sizeof(uint32_t)];
//    uint8_t version[sizeof(uint32_t)];
//};

enum class HeaderFieldId: uint8_t{
    EndOfHeader = 0,
    Comment = 1,
    CipherID = 2,
    CompressionFlags = 3,
    MasterSeed = 4,
    TransformSeed = 5,
    TransformRounds = 6,
    EncryptionIV = 7,
    ProtectedStreamKey = 8,
    StreamStartBytes = 9,
    InnerRandomStreamID = 10,
    Max
};

//struct __attribute__((gcc_struct, packed)) HeaderField{
//    HeaderFieldId id;
//    uint8_t size[sizeof(uint16_t)];
//};

//static const char FileSignature[8] = {0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5 };
static const uint32_t FileSignature1 = 0x9AA2D903;
static const uint32_t FileSignature2 = 0xB54BFB67;

/// KeePass 2.07 has version 1.01, 2.08 has 1.02, 2.09 has 2.00,
/// 2.10 has 2.02, 2.11 has 2.04, 2.15 has 3.00, 2.20 has 3.01.
/// The first 2 bytes are critical (i.e. loading will fail, if the
/// file version is too high), the last 2 bytes are informational.
static const uint32_t FileVersion32 = 0x00030001;

static const uint32_t FileVersionCriticalMask = 0xFFFF0000;

// KeePass 1.x signature
//static const char FileSignatureOld[8] = {0x03, 0xD9, 0xA2, 0x9A, 0x65, 0xFB, 0x4B, 0xB5 };
static const uint32_t FileSignatureOld1 = 0x9AA2D903;
static const uint32_t FileSignatureOld2 = 0xB54BFB65;
// KeePass 2.x pre-release (alpha and beta) signature
static const uint32_t FileSignaturePreRelease1 = 0x9AA2D903;
static const uint32_t FileSignaturePreRelease2 = 0xB54BFB66;

namespace String{

static constexpr char DocNode[] = "KeePassFile";
static constexpr char Meta[] = "Meta";
static constexpr char Root[] = "Root";
static constexpr char Group[] = "Group";
static constexpr char Entry[] = "Entry";

static constexpr char Generator[] = "Generator";
static constexpr char HeaderHash[] = "HeaderHash";
static constexpr char DbName[] = "DatabaseName";
static constexpr char DbNameChanged[] = "DatabaseNameChanged";
static constexpr char DbDesc[] = "DatabaseDescription";
static constexpr char DbDescChanged[] = "DatabaseDescriptionChanged";
static constexpr char DbDefaultUser[] = "DefaultUserName";
static constexpr char DbDefaultUserChanged[] = "DefaultUserNameChanged";
static constexpr char DbMntncHistoryDays[] = "MaintenanceHistoryDays";
static constexpr char DbColor[] = "Color";
static constexpr char DbKeyChanged[] = "MasterKeyChanged";
static constexpr char DbKeyChangeRec[] = "MasterKeyChangeRec";
static constexpr char DbKeyChangeForce[] = "MasterKeyChangeForce";
static constexpr char RecycleBinEnabled[] = "RecycleBinEnabled";
static constexpr char RecycleBinUuid[] = "RecycleBinUUID";
static constexpr char RecycleBinChanged[] = "RecycleBinChanged";
static constexpr char EntryTemplatesGroup[] = "EntryTemplatesGroup";
static constexpr char EntryTemplatesGroupChanged[] = "EntryTemplatesGroupChanged";
static constexpr char HistoryMaxItems[] = "HistoryMaxItems";
static constexpr char HistoryMaxSize[] = "HistoryMaxSize";
static constexpr char LastSelectedGroup[] = "LastSelectedGroup";
static constexpr char LastTopVisibleGroup[] = "LastTopVisibleGroup";

static constexpr char MemoryProt[] = "MemoryProtection";
static constexpr char ProtTitle[] = "ProtectTitle";
static constexpr char ProtUserName[] = "ProtectUserName";
static constexpr char ProtPassword[] = "ProtectPassword";
static constexpr char ProtUrl[] = "ProtectURL";
static constexpr char ProtNotes[] = "ProtectNotes";
static constexpr char ProtAutoHide[] = "AutoEnableVisualHiding";

static constexpr char CustomIcons[] = "CustomIcons";
static constexpr char CustomIconItem[] = "Icon";
static constexpr char CustomIconItemID[] = "UUID";
static constexpr char CustomIconItemData[] = "Data";

static constexpr char AutoType[] = "AutoType";
static constexpr char History[] = "History";

static constexpr char Name[] = "Name";
static constexpr char Notes[] = "Notes";
static constexpr char Uuid[] = "UUID";
static constexpr char Icon[] = "IconID";
static constexpr char CustomIconID[] = "CustomIconUUID";
static constexpr char FgColor[] = "ForegroundColor";
static constexpr char BgColor[] = "BackgroundColor";
static constexpr char OverrideUrl[] = "OverrideURL";
static constexpr char Times[] = "Times";
static constexpr char Tags[] = "Tags";

static constexpr char CreationTime[] = "CreationTime";
static constexpr char LastModTime[] = "LastModificationTime";
static constexpr char LastAccessTime[] = "LastAccessTime";
static constexpr char ExpiryTime[] = "ExpiryTime";
static constexpr char Expires[] = "Expires";
static constexpr char UsageCount[] = "UsageCount";
static constexpr char LocationChanged[] = "LocationChanged";

static constexpr char GroupDefaultAutoTypeSeq[] = "DefaultAutoTypeSequence";
static constexpr char EnableAutoType[] = "EnableAutoType";
static constexpr char EnableSearching[] = "EnableSearching";

static constexpr char String[] = "String";
static constexpr char Binary[] = "Binary";
static constexpr char Key[] = "Key";
static constexpr char Value[] = "Value";

static constexpr char AutoTypeEnabled[] = "Enabled";
static constexpr char AutoTypeObfuscation[] = "DataTransferObfuscation";
static constexpr char AutoTypeDefaultSeq[] = "DefaultSequence";
static constexpr char AutoTypeItem[] = "Association";
static constexpr char Window[] = "Window";
static constexpr char KeystrokeSequence[] = "KeystrokeSequence";

static constexpr char Binaries[] = "Binaries";

static constexpr char IsExpanded[] = "IsExpanded";
static constexpr char LastTopVisibleEntry[] = "LastTopVisibleEntry";

static constexpr char DeletedObjects[] = "DeletedObjects";
static constexpr char DeletedObject[] = "DeletedObject";
static constexpr char DeletionTime[] = "DeletionTime";


static constexpr char CustomData[] = "CustomData";
static constexpr char StringDictExItem[] = "Item";

static constexpr char False[] = "False";
static constexpr char True[] = "True";

static constexpr char AttrId[] = "ID";
static constexpr char AttrRef[] = "Ref";
static constexpr char AttrProtected[] = "Protected";
static constexpr char AttrProtectedInMemPlainXml[] = "ProtectInMemory";
static constexpr char AttrCompressed[] = "Compressed";

static constexpr char TagSeparators[] = ",;:";

}

//ToDo: move or even unite it with XmlReader?
//class DatabaseFile{
//public:
//    inline DatabaseFile(Database::Ptr database) noexcept
//        :database(std::move(database))
//    {}

//    Database::Ptr database;
//    std::map<XML::String, std::shared_ptr<SafeVector<uint8_t>>> binaries;
//};

//-------------------------------------------------------------------------------

class XmlReader: public XML::InputBufferTextReader{
private:
    RandomStream::Ptr cryptoRandomStream;

public:

    XmlReader(Input* input, xmlCharEncoding encoding, RandomStream::Ptr cryptoRandomStream)
        :InputBufferTextReader(input, encoding),
          cryptoRandomStream(std::move(cryptoRandomStream))
    {}

    inline RandomStream* randomStream() const noexcept{
        return cryptoRandomStream.get();
    }

    inline RandomStream::Ptr takeRandomStream() noexcept{
        return std::move(cryptoRandomStream);
    }

};

class XmlWriter: public XML::OutputBufferTextWriter{
private:
    RandomStream::Ptr cryptoRandomStream;

public:

    XmlWriter(Output* output, RandomStream::Ptr cryptoRandomStream)
        :OutputBufferTextWriter(output),
          cryptoRandomStream(std::move(cryptoRandomStream))
    {}

    inline RandomStream* randomStream() const noexcept{
        return cryptoRandomStream.get();
    }

    inline RandomStream::Ptr takeRandomStream() noexcept{
        return std::move(cryptoRandomStream);
    }

    template <typename T, typename ...Args>
    void write(const T& t, Args&& ...args);

//    template <typename T, typename ...Args>
//    void write(const typename T::ParsedType& t, Args&& ...args);

    template <typename T, typename ...Args>
    void write(const typename Parser<T>::WrittenType t, Args&& ...args);

    template <typename T, typename ...Args>
    void writeElement(const char* tagName, const T& t, Args&& ...args){
        writeStartElement(tagName);
        write(t, std::forward<Args>(args)...);
        writeEndElement();
    }

    template <typename T, typename ...Args>
    void writeElement(const char* tagName, typename Parser<T>::WrittenType t, Args&& ...args){
        writeStartElement(tagName);
        write<T>(t, std::forward<Args>(args)...);
        writeEndElement();
    }

};

//-------------------------------------------------------------------------------

class XmlReaderLink: public Pipeline::InLink, public XML::InputBufferTextReader::Input{
private:

    virtual int read(char* buffer, int len) override;
    virtual void close() override;

    Pipeline::BufferPtr current;
    std::size_t currentPos;

    Database::File::Settings fileSettings;
    SafeVector<uint8_t> fprotectedStreamKey;

    std::promise<Database::Ptr> finishedPromise;
public:

    inline XmlReaderLink(const Database::File::Settings& settings, const SafeVector<uint8_t>& protectedStreamKey) noexcept
        :currentPos(0),
          fileSettings(settings),
          fprotectedStreamKey(std::move(protectedStreamKey))
    {}

    inline std::future<Database::Ptr> getFuture(){
        return finishedPromise.get_future();
    }

    virtual void runThread() override;

};

//--------------------------------------------------------------------------------

class XmlWriterLink: public Pipeline::OutLink, public XML::OutputBufferTextWriter::Output{
private:

    int write(const char* buffer, int len) override;
    void close() override;

    Pipeline::BufferPtr current;
    std::size_t currentPos;

    const Database* database;
    SafeVector<uint8_t> fprotectedStreamKey;
    std::promise<void> finishedPromise;

    int findent;
    std::array<uint8_t, 32> fheaderHash;
public:

    inline XmlWriterLink(const Database* database, SafeVector<uint8_t> protectedStreamKey) noexcept
        :currentPos(0),
          database(database),
          fprotectedStreamKey(std::move(protectedStreamKey)),
          findent(0)
    {
        memset(fheaderHash.data(), 0, fheaderHash.size());
    }

    inline void setIndent(int indent) noexcept{
        findent = indent;
    }

    inline std::array<uint8_t, 32>& headerHash() noexcept{
        return fheaderHash;
    }

    inline std::future<void> getFuture(){
        return finishedPromise.get_future();
    }

    virtual void runThread() override;

};

//--------------------------------------------------------------------------------

int XmlReaderLink::read(char* buffer, int len){
    while(currentPos >= current->size()){
        current = InLink::read();
        currentPos = 0;
        if (!current)
            return 0;
    }

    std::size_t toCopy = std::min(current->size() - currentPos, std::size_t(len));
    uint8_t* copyBuf = &current->data()[currentPos];
    currentPos += toCopy;
    std::copy(copyBuf, copyBuf+toCopy, buffer);
    return toCopy;
}

void XmlReaderLink::close(){
    while(InLink::read()); // Just skip all following data...
}

int XmlWriterLink::write(const char* buffer, int len){

    int written = 0;
    while (written < len){
        std::size_t copySize = std::min(len - written, int(Pipeline::Buffer::maxSize - currentPos));
        std::copy(buffer, buffer+copySize, current->data().data() + currentPos);
        written += copySize;
        buffer += copySize;
        currentPos += copySize;
        if (currentPos == Pipeline::Buffer::maxSize){
            OutLink::write(std::move(current));
            current = Pipeline::BufferPtr(new Pipeline::Buffer(Pipeline::Buffer::maxSize));
            currentPos = 0;
        }
    }

    return written;
}

void XmlWriterLink::close(){
    if (currentPos){
        current->setSize(currentPos);
        OutLink::write(std::move(current));
    }
}

template <typename T>
class Parser;

template <> class Parser<char*>;
template <> class Parser<const char*>;
template <> class Parser<XML::String>;
template <> class Parser<XorredBuffer>;
template <> class Parser<int32_t>;
template <> class Parser<int64_t>;
template <> class Parser<uint32_t>;
template <> class Parser<uint64_t>;
template <> class Parser<bool>;
template <> class Parser<std::string>;
template <> class Parser<std::vector<uint8_t>>;
template <> class Parser<SafeString<char>>;
template <> class Parser<SafeVector<uint8_t>>;
template <std::size_t size>
class Parser<std::array<uint8_t, size>>;
template <> class Parser<Uuid>;
class Time;
template <> class Parser<Time>;
class Tags;
template <> class Parser<Tags>;
template <> class Parser<CustomIcon::Ptr>;
template <> class Parser<CustomIcons>;
template <> class Parser<MemoryProtectionFlags>;
template <> class Parser<Database::Meta::Binary>;
template <> class Parser<Database::Meta::Binaries>;
class StringTag;
template <> class Parser<StringTag>;
class CustomDataItemTag;
template <> class Parser<CustomDataItemTag>;
class CustomDataTag;
template <> class Parser<CustomDataTag>;
template <> class Parser<Database::Meta>;
template <> class Parser<Database::Version::AutoType::Association>;
template <> class Parser<Database::Version::AutoType>;
template <> class Parser<Times>;

template <> class Parser<Database::Version::Binary::Value>;
template <> class Parser<Database::Version::Binary>;
//template <> class Parser<Database::Version::Binaries>;
//template <> class Parser<Database::Version>;
template <> class Parser<Database::Version::Ptr>;
template <> class Parser<std::vector<Database::Version::Ptr>>;
template <> class Parser<Database::Entry::Ptr>;
template <> class Parser<Database::Group::Ptr>;
template <> class Parser<std::pair<Uuid, time_t>>;
template <> class Parser<std::map<Uuid, time_t>>;
class RootTag;
template <> class Parser<RootTag>;
template <> class Parser<Database>;

//------------------------------------------------------------------------------

template <typename T, typename ...Args>
auto parse(XmlReader& reader, Args&&... args) -> decltype(Parser<T>::parseNew(reader, std::forward<Args>(args)...)){
    return Parser<typename std::remove_cv<typename std::remove_reference<T>::type>::type>::parseNew(reader, std::forward<Args>(args)...);
}

template <typename T, typename ...Args>
void XmlWriter::write(const T& t, Args&& ...args){
    Parser<typename std::remove_cv<typename std::remove_reference<T>::type>::type>::writeOld(*this, t, std::forward<Args>(args)...);
}

template <typename T, typename ...Args>
void XmlWriter::write(typename Parser<T>::WrittenType t, Args&& ...args){
    Parser<typename std::remove_cv<typename std::remove_reference<T>::type>::type>::writeOld(*this, t, std::forward<Args>(args)...);
}


//------------------------------------------------------------------------------

template <typename Parser, typename tResultType>
class TagParser{
public:
    typedef tResultType ResultType;

    template <typename ...Args>
    static ResultType parseNew(XmlReader& reader, Args&&... args);
};

// This is necesary to iterate over unknown tags - this has to be done to
// keep hash function used to protect stuff synchronized with xml content.
template <>
class TagParser<void, void>{
public:
    typedef void ResultType;

    static void parseNew(XmlReader& reader){

        if (!reader.isEmpty()){
            reader.expectRead();

            xmlReaderTypes type;
            while ((type = reader.nodeType()) != XML_READER_TYPE_END_ELEMENT){
                //std::cout << XML::toString(reader.nodeType()) << ": " << reader.localName() << std::endl;

                if (type == XML_READER_TYPE_ELEMENT){
                    parseNew(reader);
                }

                reader.expectNext();
            }
        }

    }
};

template <typename Parser, typename tResultType>
template <typename ...Args>
tResultType TagParser<Parser, tResultType>::parseNew(XmlReader& reader, Args&&... args){
    Parser result(std::forward<Args>(args)...);

    if (!reader.isEmpty()){
        reader.expectRead();

        xmlReaderTypes type;
        while ((type = reader.nodeType()) != XML_READER_TYPE_END_ELEMENT){

            if (type == XML_READER_TYPE_ELEMENT){
                if (!result.tag(reader))
                    TagParser<void, void>::parseNew(reader);
            }

            reader.expectNext();
        }
    }

    return result.takeResult();
}

//------------------------------------------------------------------------------

template <typename Parser, typename tItemType, typename ItemParseAs = tItemType, typename ...Args>
class VectorTagParser: public TagParser<VectorTagParser<Parser, tItemType, ItemParseAs, Args...>, std::vector<tItemType>>{
public:

    typedef tItemType ItemType;

    inline VectorTagParser(Args&& ...args) noexcept(noexcept(std::forward_as_tuple(args...)))
        :parserParameters(std::forward_as_tuple(args...))
    {}

    bool tag(XmlReader& reader){
        std::string localName = reader.localName();
        if (localName == Parser::itemTagName){
            value.push_back(invokeParse(reader, std::index_sequence_for<Args...>()));
        }else{
            return false;
        }
        return true;
    }

    inline std::vector<ItemType> takeResult(){
        return std::move(value);
    }

    template <typename ...UnArgs>
    static void writeOld(XmlWriter& writer, const std::vector<ItemType>& items, const UnArgs&... args){
        for (const ItemType& item: items){
            writer.writeStartElement(Parser::itemTagName);
            writer.write(item, args...);
            writer.writeEndElement();
        }
    }

private:


    template <std::size_t... I>
    inline auto invokeParse(XmlReader& reader, std::index_sequence<I...>){
        return parse<ItemParseAs>(reader, std::get<I>(parserParameters)...);
    }

    std::tuple<Args...> parserParameters;
    std::vector<ItemType> value;
};

template <typename Parser, typename tItemType, typename ItemParseAs = tItemType, typename ...Args>
class ListTagParser: public TagParser<ListTagParser<Parser, tItemType, ItemParseAs, Args...>, std::list<tItemType>>{
public:

    typedef tItemType ItemType;

    inline ListTagParser(Args&& ...args) noexcept(noexcept(std::make_tuple(std::forward<Args>(args)...)))
        :parserParameters(std::make_tuple(std::forward<Args>(args)...))
    {}

    bool tag(XmlReader& reader){
        std::string localName = reader.localName();
        if (localName == Parser::itemTagName){
            value.push_back(invokeParse(reader, std::index_sequence_for<Args...>()));
        }else{
            return false;
        }
        return true;
    }

    inline std::list<ItemType> takeResult(){
        return std::move(value);
    }

    template <typename ...UnArgs>
    static void writeOld(XmlWriter& writer, const std::list<ItemType>& items, const UnArgs&... args){
        for (const ItemType& item: items){
            writer.writeStartElement(Parser::itemTagName);
            writer.write(item, args...);
            writer.writeEndElement();
        }
    }

private:


    template <std::size_t... I>
    inline auto invokeParse(XmlReader& reader, std::index_sequence<I...>){
        return parse<ItemParseAs>(reader, std::get<I>(parserParameters)...);
    }

    std::tuple<Args...> parserParameters;
    std::list<ItemType> value;
};

//------------------------------------------------------------------------------

template<>
class Parser<char*>{
public:
    static void writeOld(XmlWriter& writer, char* text){
        writer.writeString(text);
    }
};

template <>
class Parser<const char*>{
public:
    static void writeOld(XmlWriter& writer, const char* text){
        writer.writeString(text);
    }
};

template <>
class Parser<XML::String>{
public:
    static XML::String parseNew(XmlReader& reader){
        XML::String attr = reader.attribute(String::AttrProtected);
        XML::String result = reader.readString();
        if (attr && strcmp(attr.c_str(), String::True) == 0 ){
            if (result){
                SafeVector<uint8_t> xored = safeDecodeBase64(result.c_str());
                SafeVector<uint8_t> xorMask = reader.randomStream()->read(xored.size());
                xmlChar* res = result.get();
                res = std::transform(xored.begin(), xored.end(), xorMask.begin(), res, std::bit_xor<uint8_t>());
                *res = 0;
            }
        }

        return result;
    }

    static void writeOld(XmlWriter& writer, const XML::String& text){
        writer.write(text.c_str());
    }
};

template <>
class Parser<XorredBuffer>{
public:
    static XorredBuffer parseNew(XmlReader& reader){
        XML::String attr = reader.attribute(String::AttrProtected);
        XML::String result = reader.readString();
        if (result){
            if (attr && strcmp(attr.c_str(), String::True) == 0 ){
                //std::cout << "Decoding: " << result.c_str() << std::endl;
                SafeVector<uint8_t> xorred = safeDecodeBase64(result.c_str());
                SafeVector<uint8_t> mask = reader.randomStream()->read(xorred.size());
                return XorredBuffer(std::move(xorred), std::move(mask));
            }
            return XorredBuffer(result.get(), result.get() + xmlStrlen(result.get()));
        }
        return XorredBuffer();
    }

    static void writeOld(XmlWriter& writer, XorredBuffer buffer){
        if (buffer.mask().size()){
            SafeVector<uint8_t> xorBuf = writer.randomStream()->read(buffer.size());
            buffer.reXor(xorBuf);
            writer.writeAttribute(String::AttrProtected, String::True);
            writer.writeBase64(buffer.buffer());
        }else{
            //const SafeVector<uint8_t>& data = buffer.buffer();
            writer.writeString(buffer.plainString().c_str());
        }
    }

};

template <>
class Parser<int32_t>{
public:
    static int32_t parseNew(XmlReader& reader){

        XML::String s = parse<XML::String>(reader);
        const uint8_t* str = s.get();
        if (!str) return 0;

        int32_t result = 0;

        int sign = 1;
        if (*str == '-'){
            sign = -1;
            str++;
        }

        while (*str){
            uint8_t val = *str;
            if (val < '0' || val > '9')
                throw std::runtime_error("Bad integer.");
            result = result*10 + (val - '0');
            str++;
        }

        return result * sign;
    }

    static void writeOld(XmlWriter& writer, int32_t value){
        std::stringstream s;
        s << value;
        writer.write(s.str());
    }
};

template <>
class Parser<int64_t>{
public:
    static int64_t parseNew(XmlReader& reader){

        XML::String s = parse<XML::String>(reader);
        const uint8_t* str = s.get();
        if (!str) return 0;

        int64_t result = 0;

        int sign = 1;
        if (*str == '-'){
            sign = -1;
            str++;
        }

        while (*str){
            uint8_t val = *str;
            if (val < '0' || val > '9')
                throw std::runtime_error("Bad integer.");
            result = result*10 + (val - '0');
            str++;
        }

        return result * sign;
    }

    static void writeOld(XmlWriter& writer, int64_t value){
        std::stringstream s;
        s << value;
        writer.write(s.str());
    }
};

template <>
class Parser<uint32_t>{
public:
    static uint32_t parseNew(XmlReader& reader){

        XML::String s = parse<XML::String>(reader);
        const uint8_t* str = s.get();
        if (!str) return 0;

        uint32_t result = 0;

        while (*str){
            uint8_t val = *str;
            if (val < '0' || val > '9')
                throw std::runtime_error("Bad integer.");
            result = result*10 + (val - '0');
            str++;
        }

        return result;
    }

    static void writeOld(XmlWriter& writer, uint32_t value){
        std::stringstream s;
        s << value;
        writer.write(s.str());
    }
};

template <>
class Parser<uint64_t>{
public:
    static uint64_t parseNew(XmlReader& reader){

        XML::String s = parse<XML::String>(reader);
        const uint8_t* str = s.get();
        if (!str) return 0;

        uint64_t result = 0;

        while (*str){
            uint8_t val = *str;
            if (val < '0' || val > '9')
                throw std::runtime_error("Bad integer.");
            result = result*10 + (val - '0');
            str++;
        }

        return result;
    }

    static void writeOld(XmlWriter& writer, uint64_t value){
        std::stringstream s;
        s << value;
        writer.write(s.str());
    }
};

template <>
class Parser<bool>{
public:
    static bool parseNew(XmlReader& reader){
        XML::String s = parse<XML::String>(reader);
        if (!s.c_str())
            return false;

        return strcmp(s.c_str(), String::True) == 0;
    }

    static void writeOld(XmlWriter& writer, bool value){
        if (value){
            writer.write<const char*>(String::True);
        }else{
            writer.write<const char*>(String::False);
        }
    }
};

template <>
class Parser<std::string>{
public:
    static std::string parseNew(XmlReader& reader){
        XML::String str = parse<XML::String>(reader);
        if (str) return str.c_str();
        return std::string();
    }

    static void writeOld(XmlWriter& writer, const std::string& value){
        writer.write(value.c_str());
    }
};

template <>
class Parser<std::vector<uint8_t>>{
public:
    static std::vector<uint8_t> parseNew(XmlReader& reader){
        return decodeBase64(parse<std::string>(reader));
    }

    static void writeOld(XmlWriter& writer, const std::vector<uint8_t>& value){
        writer.writeBase64(value);
    }
};

template <>
class Parser<SafeString<char>>{
public:
    static SafeString<char> parseNew(XmlReader& reader){
        XML::String str = parse<XML::String>(reader);
        if (str)
            return SafeString<char>(str.c_str());
        return SafeString<char>();
    }

    static void writeOld(XmlWriter& writer, const SafeString<char>& value){
        writer.write(value.c_str());
    }
};

template <>
class Parser<SafeVector<uint8_t>>{
public:
    static SafeVector<uint8_t> parseNew(XmlReader& reader){
        return safeDecodeBase64(parse<SafeString<char>>(reader));
    }

    static void writeOld(XmlWriter& writer, const SafeVector<uint8_t>& value){
        writer.writeBase64(value);
    }
};

template <std::size_t size>
class Parser<std::array<uint8_t, size>>{
public:
    static std::array<uint8_t, size> parseNew(XmlReader& reader){
        std::vector<uint8_t> data = decodeBase64(parse<std::string>(reader));
        if (data.size() != size){
            std::stringstream s;
            s << "Invalid field size - has " << data.size() << " bytes, expected " << size << " bytes.";
            throw std::runtime_error(s.str());
        }
        std::array<uint8_t, size> result;
        std::copy(data.begin(), data.end(), result.begin());
        return result;
    }

    static void writeOld(XmlWriter& writer, const std::array<uint8_t, size>& value){
        writer.writeBase64(value);
    }
};

template <>
class Parser<Uuid>{
public:
    static Uuid parseNew(XmlReader& reader){
        return Uuid(parse<std::vector<uint8_t>>(reader));
    }

    static void writeOld(XmlWriter& writer, const Uuid& value){
        writer.writeBase64(value.raw());
    }
};

class Time;

// ToDo: some time wrapper perhaps?
// ToDo: This is terrible, is there really no portable way to do this?
template <>
class Parser<Time>{
public:
    typedef std::time_t WrittenType;

    static std::time_t parseNew(XmlReader& reader){
        XML::String s(reader.readString());
        if (!s.get())
            return 0;
        return formatTime(reinterpret_cast<const char*>(s.get()));
    }

    static void writeOld(XmlWriter& writer, std::time_t value){
        writer.write(unformatTime(value));
    }
};

class Tags;

template <>
class Parser<Tags>{
public:

    typedef const std::vector<std::string>& WrittenType;

    static std::vector<std::string> parseNew(XmlReader& reader){
        return explode(parse<std::string>(reader), String::TagSeparators);
    }

    static void writeOld(XmlWriter& writer, const std::vector<std::string>& value){
        writer.write(implode(value, String::TagSeparators[0]));
    }
};

template <>
class Parser<CustomIcon::Ptr>: public TagParser<Parser<CustomIcon::Ptr>, CustomIcon::Ptr>{
private:
    bool haveUuid;
    bool haveData;
    Uuid uuid;
    std::vector<uint8_t> data;
public:
    inline Parser() noexcept
        :haveUuid(false),
          haveData(false)
    {}

    bool tag(XmlReader& reader){

        std::string localName = reader.localName();
        if (localName == String::Uuid){
            uuid = parse<Uuid>(reader);
            haveUuid = true;
        } else if (localName == String::CustomIconItemData){
            data = parse<std::vector<uint8_t>>(reader);
            haveData = true;
        }else{
            return false;
        }
        return true;

    }

    inline CustomIcon::Ptr takeResult(){
        if (!haveUuid) throw std::runtime_error("Custom icon without UUID.");
        if (!haveData) throw std::runtime_error("Empty custom icon.");
        return CustomIcon::Ptr(new CustomIcon(uuid, std::move(data)));
    }

    static void writeOld(XmlWriter& writer, const CustomIcon::Ptr& value){
        writer.writeElement(String::Uuid, value->uuid());
        writer.writeElement(String::CustomIconItemData, value->data());
    }


};

template <>
class Parser<CustomIcons>: public VectorTagParser<Parser<CustomIcons>, CustomIcon::Ptr>{
public:
    typedef CustomIcon::Ptr ItemType;
    static constexpr const char* itemTagName = String::CustomIconItem;
};



template <>
class Parser<MemoryProtectionFlags>: public TagParser<Parser<MemoryProtectionFlags>, MemoryProtectionFlags>{
private:
    MemoryProtectionFlags data;
public:
    inline Parser() noexcept{
        data.set(MemoryProtection::Password);
    }

    bool tag(XmlReader& reader){

        std::string localName = reader.localName();
        if (localName == String::ProtTitle){
            data.set(MemoryProtection::Title, parse<bool>(reader));
        } else if (localName == String::ProtUserName){
            data.set(MemoryProtection::UserName, parse<bool>(reader));
        } else if (localName == String::ProtPassword){
            data.set(MemoryProtection::Password, parse<bool>(reader));
        } else if (localName == String::ProtUrl){
            data.set(MemoryProtection::Url, parse<bool>(reader));
        } else if (localName == String::ProtNotes){
            data.set(MemoryProtection::Notes, parse<bool>(reader));
        } else if (localName == String::ProtAutoHide){
            data.set(MemoryProtection::AutoHide, parse<bool>(reader));
        } else {
            return false;
        }
        return true;

    }

    inline MemoryProtectionFlags takeResult(){
        return std::move(data);
    }

    static void writeOld(XmlWriter& writer, const MemoryProtectionFlags& value){
        writer.writeElement(String::ProtTitle, value.test(MemoryProtection::Title));
        writer.writeElement(String::ProtUserName, value.test(MemoryProtection::UserName));
        writer.writeElement(String::ProtPassword, value.test(MemoryProtection::Password));
        writer.writeElement(String::ProtUrl, value.test(MemoryProtection::Url));
        writer.writeElement(String::ProtNotes, value.test(MemoryProtection::Notes));
        writer.writeElement(String::ProtAutoHide, value.test(MemoryProtection::AutoHide));
    }


};

template <>
class Parser<Database::Meta::Binary>{
public:

    typedef const SafeVector<uint8_t>& WrittenType;

    static std::shared_ptr<SafeVector<uint8_t>> parseNew(XmlReader& reader){

        XML::String compressed = reader.attribute(String::AttrCompressed);
        SafeVector<uint8_t> result = parse<SafeVector<uint8_t>>(reader);

        if (compressed && strcmp(compressed.c_str(), String::True) == 0) // ToDo: is this correct? Check original keepass2 source.
            return std::make_shared<SafeVector<uint8_t>>(Zlib::Inflater::oneShot(result, MAX_WBITS | 16));
        return std::make_shared<SafeVector<uint8_t>>(std::move(result));
    }

    static void writeOld(XmlWriter& writer, const SafeVector<uint8_t>& data, bool compress = true){
        SafeVector<uint8_t> tmp;
        if (compress){
            tmp = Zlib::Deflater::oneShot(data, MAX_WBITS | 16);
            writer.writeAttribute(String::AttrCompressed, String::True);
            writer.writeBase64(tmp);
        }else{
            writer.writeBase64(data);
        }
    }



};

template <>
class Parser<Database::Meta::Binaries>: public TagParser<Parser<Database::Meta::Binaries>, std::map<std::string, std::shared_ptr<SafeVector<uint8_t>>>>{
private:

    class Writer{
    private:
        std::set<const SafeVector<uint8_t>*> written;
        XmlWriter& writer;
        bool compress;

    public:
        inline Writer(XmlWriter& writer, bool compress) noexcept
            :writer(writer),
              compress(compress)
        {}

        void write(const Database::Group* group){
            for (size_t i=0; i<group->groups(); ++i){
                write(group->group(i));
            }
            for (size_t i=0; i<group->entries(); ++i){
                write(group->entry(i));
            }
        }

        void write(const Database::Entry* entry){
            for (size_t i=0; i<entry->versions(); ++i){
                write(entry->version(i));
            }
        }

        void write(const Database::Version* version){
            for (const std::pair<std::string, std::shared_ptr<SafeVector<uint8_t>>>& item: version->binaries){
                const SafeVector<uint8_t>* ptr = item.second.get();
                if (written.find(ptr) == written.end()){
                    writer.writeStartElement(String::Binary);
                    std::stringstream s;
                    s << ptr;
                    writer.writeAttribute(String::AttrId, s.str().c_str());
                    writer.write<Database::Meta::Binary>(*item.second, compress);
                    writer.writeEndElement();
                    written.insert(ptr);
                }
            }
        }
    };


    std::map<std::string, std::shared_ptr<SafeVector<uint8_t>>> data;
public:
    typedef const Database::Group* WrittenType;

    bool tag(XmlReader& reader){

        std::string localName = reader.localName();
        if (localName == String::Binary){
            XML::String id = reader.attribute(String::AttrId);
            if (id){ //Apparently KeePassLib is ignoring binaries without id...
                std::string sid(id.c_str());
                auto pos = data.lower_bound(sid);
                if (pos == data.end() || pos->first != sid)
                    data.insert(pos,
                                std::make_pair(
                                    std::move(sid),
                                    parse<Database::Meta::Binary>(reader)
                                    ));
            }
        } else {
            return false;
        }
        return true;

    }

    inline std::map<std::string, std::shared_ptr<SafeVector<uint8_t>>> takeResult(){
        return std::move(data);
    }

    static void writeOld(XmlWriter& writer, const Database::Group* group, bool compress){
        Writer w(writer, compress);
        w.write(group);
    }

};

class StringTag;

template <>
class Parser<StringTag>: public TagParser<Parser<StringTag>, std::pair<std::string, XorredBuffer>>{
private:
    std::pair<std::string, XorredBuffer> data;
public:

    typedef const std::pair<std::string, XorredBuffer>& WrittenType;

    bool tag(XmlReader& reader){

        std::string localName = reader.localName();
        if (localName == String::Key){
            data.first = parse<std::string>(reader);
        } else if (localName == String::Value){
            data.second = parse<XorredBuffer>(reader);
        } else {
            return false;
        }
        return true;

    }

    inline std::pair<std::string, XorredBuffer> takeResult(){
        return std::move(data);
    }

    static void writeOld(XmlWriter& writer, const std::pair<std::string, XorredBuffer>& data){
        writer.writeElement(String::Key, data.first);
        writer.writeElement(String::Value, data.second);
    }


};

class CustomDataItemTag;

template <>
class Parser<CustomDataItemTag>: public TagParser<Parser<CustomDataItemTag>, std::pair<std::string, std::string>>{
private:
    std::pair<std::string, std::string> data;
public:
    typedef const std::pair<std::string, std::string>& WrittenType;

    bool tag(XmlReader& reader){

        std::string localName = reader.localName();
        if (localName == String::Key){
            data.first = parse<std::string>(reader);
        } else if (localName == String::Value){
            data.second = parse<std::string>(reader);
        } else {
            return false;
        }
        return true;

    }

    inline std::pair<std::string, std::string> takeResult(){
        return std::move(data);
    }

    static void writeOld(XmlWriter& writer, const std::pair<std::string, std::string>& data){
        writer.writeElement(String::Key, data.first);
        writer.writeElement(String::Value, data.second);
    }

};

class CustomDataTag;

template <>
class Parser<CustomDataTag>: public TagParser<Parser<CustomDataTag>, std::map<std::string, std::string>>{
private:
    std::map<std::string, std::string> data;
public:
    typedef const std::map<std::string, std::string>& WrittenType;

    bool tag(XmlReader& reader){

        std::string localName = reader.localName();
        if (localName == String::StringDictExItem){
            data.insert(parse<CustomDataItemTag>(reader));
        } else {
            return false;
        }
        return true;

    }

    inline std::map<std::string, std::string> takeResult(){
        return std::move(data);
    }

    static void writeOld(XmlWriter& writer, const std::map<std::string, std::string>& data){
        for (const std::pair<std::string, std::string>& item: data){
            writer.writeElement<CustomDataItemTag>(String::StringDictExItem, item);
        }
    }

};

template <>
class Parser<Database::Meta>: public TagParser<Parser<Database::Meta>, Database::Meta>{
private:
    Database::Meta data;
public:
    typedef const Database* WrittenType;

    inline Parser(const Database::File::Settings& settings) noexcept
        :data(settings)
    {}

    bool tag(XmlReader& reader){

        std::string localName = reader.localName();
        // ToDo: headerHash field!!!
        if (localName == String::DbName){
            data.settings->fname = parse<std::string>(reader);
        }else if (localName == String::DbNameChanged){
            data.settings->fnameChanged = parse<Time>(reader);
        }else if (localName == String::DbDesc){
            data.settings->fdescription = parse<std::string>(reader);
        }else if (localName == String::DbDescChanged){
            data.settings->fdescriptionChanged = parse<Time>(reader);
        }else if (localName == String::DbDefaultUser){
            data.settings->fdefaultUsername = parse<std::string>(reader);
        }else if (localName == String::DbDefaultUserChanged){
            data.settings->fdefaultUsernameChanged = parse<Time>(reader);
        }else if (localName == String::DbMntncHistoryDays){
            data.settings->maintenanceHistoryDays = parse<int>(reader);
        }else if (localName == String::DbColor){
            data.settings->color = parse<std::string>(reader);
        }else if (localName == String::DbKeyChanged){
            data.settings->masterKeyChanged = parse<Time>(reader);
        }else if (localName == String::DbKeyChangeRec){
            data.settings->masterKeyChangeRec = parse<int64_t>(reader);
        }else if (localName == String::DbKeyChangeForce){
            data.settings->masterKeyChangeForce = parse<int64_t>(reader);
        }else if (localName == String::MemoryProt){
            data.settings->memoryProtection = parse<MemoryProtectionFlags>(reader);
        }else if (localName == String::CustomIcons){
            data.customIcons = parse<CustomIcons>(reader);
        }else if (localName == String::RecycleBinEnabled){
            data.settings->recycleBinEnabled = parse<bool>(reader);
        }else if (localName == String::RecycleBinUuid){
            data.recycleBinUUID = parse<Uuid>(reader);
        }else if (localName == String::RecycleBinChanged){
            data.recycleBinChanged = parse<Time>(reader);
        }else if (localName == String::EntryTemplatesGroup){
            data.templatesUUID = parse<Uuid>(reader);
        }else if (localName == String::EntryTemplatesGroupChanged){
            data.templatesChanged = parse<Time>(reader);
        }else if (localName == String::HistoryMaxItems){
            data.settings->historyMaxItems = parse<int>(reader);
        }else if (localName == String::HistoryMaxSize){
            data.settings->historyMaxSize = parse<int64_t>(reader);
        }else if (localName == String::LastSelectedGroup){
            data.settings->lastSelectedGroup = parse<Uuid>(reader);
        }else if (localName == String::LastTopVisibleGroup){
            data.settings->lastTopVisibleGroup = parse<Uuid>(reader);
        }else if (localName == String::Binaries){
            auto tmp = parse<Database::Meta::Binaries>(reader);
            using std::swap;
            swap(tmp, data.binaries);
        }else if (localName == String::CustomData){
            data.customData = parse<CustomDataTag>(reader);
        } else {
            return false;
        }
        return true;

    }

    inline Database::Meta takeResult(){
        return std::move(data);
    }

    static void writeOld(XmlWriter& writer, const Database* data, const std::array<uint8_t, 32>& headerHash){
        const Database::Settings& settings = data->settings();

        writer.writeElement<const char*>(String::Generator, "LibKeePass2++ " KEEPASS2PP_VERSION );
        writer.writeElement(String::HeaderHash, headerHash);
        writer.writeElement(String::DbName, settings.name());
        writer.writeElement<Time>(String::DbNameChanged, settings.nameChanged());
        writer.writeElement(String::DbDesc, settings.description());
        writer.writeElement<Time>(String::DbDescChanged, settings.descriptionChanged());
        writer.writeElement(String::DbDefaultUser, settings.defaultUsername());
        writer.writeElement<Time>(String::DbDefaultUserChanged, settings.defaultUsernameChanged());
        writer.writeElement(String::DbMntncHistoryDays, settings.maintenanceHistoryDays);
        writer.writeElement(String::DbColor, settings.color);
        writer.writeElement<Time>(String::DbKeyChanged, settings.masterKeyChanged);
        writer.writeElement(String::DbKeyChangeRec, settings.masterKeyChangeRec);
        writer.writeElement(String::DbKeyChangeForce, settings.masterKeyChangeForce);
        writer.writeElement(String::MemoryProt, settings.memoryProtection);
        writer.writeElement(String::CustomIcons, data->fcustomIcons);
        writer.writeElement(String::RecycleBinEnabled, settings.recycleBinEnabled);
        if (data->recycleBin()){
            writer.writeElement(String::RecycleBinUuid, data->recycleBin()->uuid());
        }else{
            writer.writeElement(String::RecycleBinUuid, Uuid::nil());
        }
        writer.writeElement<Time>(String::RecycleBinChanged, data->recycleBinChanged());
        if (data->templates()){
            writer.writeElement(String::EntryTemplatesGroup, data->templates()->uuid());
        }else{
            writer.writeElement(String::EntryTemplatesGroup, Uuid::nil());
        }
        writer.writeElement<Time>(String::EntryTemplatesGroupChanged, data->templatesChanged());
        writer.writeElement(String::HistoryMaxItems, settings.historyMaxItems);
        writer.writeElement(String::HistoryMaxSize, settings.historyMaxSize);
        writer.writeElement(String::LastSelectedGroup, settings.lastSelectedGroup);
        writer.writeElement(String::LastTopVisibleGroup, settings.lastTopVisibleGroup);
        writer.writeElement<Database::Meta::Binaries>(String::Binaries, data->root(), false); // ToDo lead compression even further up here?
        writer.writeElement<CustomDataTag>(String::CustomData, data->customData);
    }

};

template <>
class Parser<Database::Version::AutoType::Association>: public TagParser<Parser<Database::Version::AutoType::Association>, Database::Version::AutoType::Association>{
private:
    Database::Version::AutoType::Association data;
public:
    bool tag(XmlReader& reader){

        std::string localName = reader.localName();
        if (localName == String::Window){
            data.window = parse<std::string>(reader);
        } else if (localName == String::KeystrokeSequence){
            data.sequence = parse<std::string>(reader);
        } else {
            return false;
        }
        return true;

    }

    inline Database::Version::AutoType::Association takeResult(){
        return std::move(data);
    }

    static void writeOld(XmlWriter& writer, const Database::Version::AutoType::Association& data){
        writer.writeElement(String::Window, data.window);
        writer.writeElement(String::KeystrokeSequence, data.sequence);
    }

};

template <>
class Parser<Database::Version::AutoType>: public TagParser<Parser<Database::Version::AutoType>, Database::Version::AutoType>{
private:
    Database::Version::AutoType data;
public:
    bool tag(XmlReader& reader){

        std::string localName = reader.localName();
        if (localName == String::AutoTypeEnabled){
            data.enabled = parse<bool>(reader);
        } else if (localName == String::AutoTypeObfuscation){
            data.obfuscationOptions = Database::Version::AutoType::ObfuscationOptions(parse<int>(reader));
        } else if (localName == String::AutoTypeDefaultSeq){
            data.defaultSequence = parse<std::string>(reader);
        } else if (localName == String::AutoTypeItem){
            data.items.push_back(parse<Database::Version::AutoType::Association>(reader));
        } else {
            return false;
        }
        return true;

    }

    inline Database::Version::AutoType takeResult(){
        return std::move(data);
    }

    static void writeOld(XmlWriter& writer, const Database::Version::AutoType& data){
        writer.writeElement(String::AutoTypeEnabled, data.enabled);
        writer.writeElement(String::AutoTypeObfuscation, int(data.obfuscationOptions));
        writer.writeElement(String::AutoTypeDefaultSeq, data.defaultSequence);
        for (const Database::Version::AutoType::Association& item: data.items){
            writer.writeElement(String::AutoTypeItem, item);
        }
    }

};

template <>
class Parser<Times>: public TagParser<Parser<Times>, Times>{
private:
    Times data;
public:
    bool tag(XmlReader& reader){

        std::string localName = reader.localName();
        if (localName == String::CreationTime){
            data.creation = parse<Time>(reader);
        } else if (localName == String::LastModTime){
            data.lastModification = parse<Time>(reader);
        } else if (localName == String::LastAccessTime){
            data.lastAccess = parse<Time>(reader);
        } else if (localName == String::ExpiryTime){
            data.expiry = parse<Time>(reader);
        } else if (localName == String::Expires){
            data.expires = parse<bool>(reader);
        } else if (localName == String::UsageCount){
            data.usageCount = parse<uint64_t>(reader);
        } else if (localName == String::LocationChanged){
            data.locationChanged = parse<Time>(reader);
        } else {
            return false;
        }
        return true;

    }

    inline Times takeResult(){
        return std::move(data);
    }

    static void writeOld(XmlWriter& writer, const Times& data){
        writer.writeElement<Time>(String::CreationTime, data.creation);
        writer.writeElement<Time>(String::LastModTime, data.lastModification);
        writer.writeElement<Time>(String::LastAccessTime, data.lastAccess);
        writer.writeElement<Time>(String::ExpiryTime, data.expiry);
        writer.writeElement(String::Expires, data.expires);
        writer.writeElement(String::UsageCount, data.usageCount);
        writer.writeElement<Time>(String::LocationChanged, data.locationChanged);
    }


};

template <>
class Parser<Database::Version::Binary::Value>{
public:

    typedef const SafeVector<uint8_t>& WrittenType;

    static std::shared_ptr<SafeVector<uint8_t>> parseNew(XmlReader& reader, const Database::Meta& meta){
        XML::String id = reader.attribute(String::AttrRef);
        auto idpos = meta.binaries.find(id?id.c_str():"");
        if (idpos != meta.binaries.end()){
            parse<XML::String>(reader); // Skip the tag content
            return idpos->second;
        }

        return parse<Database::Meta::Binary>(reader);
    }

    static void writeOld(XmlWriter& writer, const SafeVector<uint8_t>& data){
         writer.write<Database::Meta::Binary>(data);
    }


};

template <>
class Parser<Database::Version::Binary>: public TagParser<Parser<Database::Version::Binary>, std::pair<std::string, std::shared_ptr<SafeVector<uint8_t>>>>{
private:
    const Database::Meta& meta;
    std::pair<std::string, std::shared_ptr<SafeVector<uint8_t>>> data;

public:
    typedef const std::pair<std::string, std::shared_ptr<SafeVector<uint8_t>>>& WrittenType;

    inline Parser(const Database::Meta& meta)
        :meta(meta)
    {}

    bool tag(XmlReader& reader){

        std::string localName = reader.localName();
        if (localName == String::Key){
            data.first = parse<std::string>(reader);
        } else if (localName == String::Value){
            data.second = parse<Database::Version::Binary::Value>(reader, meta);
        } else {
            return false;
        }
        return true;

    }

    inline std::pair<std::string, std::shared_ptr<SafeVector<uint8_t>>> takeResult(){
        return std::move(data);
    }

    static void writeOld(XmlWriter& writer, const std::pair<std::string, std::shared_ptr<SafeVector<uint8_t>>>& data){
        writer.writeElement(String::Key, data.first);
        std::stringstream s;
        s << data.second.get();
        writer.writeStartElement(String::Value);
        writer.writeAttribute(String::AttrRef, s.str().c_str());
        writer.writeEndElement();
    }

};

template <>
class Parser<Database::Version>: public TagParser<Parser<Database::Version>, Database::Version::Ptr>{
private:
    const Database::Meta& meta;
    Database::Version::Ptr version;
    StandardIcon standardIcon;
    Uuid customIcon;
public:

    typedef const Database::Version* WrittenType;

    inline Parser(const Database::Meta& meta, Database::Entry* parent)
        :meta(meta),
          version(new Database::Version(parent)),
          standardIcon(StandardIcon::Key),
          customIcon(Uuid::nil())
    {}

    inline bool tag(XmlReader& reader){
        return tag(reader, reader.localName());
    }

    bool tag(XmlReader& reader, std::string localName){

        //                if (localName == String::Uuid){
        //                        parse<XML::String>(reader); // Just ignore uuid here...
        //                } else
        if (localName == String::Icon){
            standardIcon = StandardIcon(parse<int>(reader));
        } else if (localName == String::CustomIconID){
            customIcon = parse<Uuid>(reader);
        } else if (localName == String::FgColor){
            version->fgColor = parse<std::string>(reader);
        } else if (localName == String::BgColor){
            version->bgColor = parse<std::string>(reader);
        } else if (localName == String::OverrideUrl){
            version->overrideUrl = parse<std::string>(reader);
        } else if (localName == String::Tags){
            version->tags = parse<Tags>(reader);
        } else if (localName == String::Times){
            version->times = parse<Times>(reader);
        } else if (localName == String::String){
            version->strings.insert(parse<StringTag>(reader));
        } else if (localName == String::Binary){
            auto binaryItem = parse<Database::Version::Binary>(reader, meta);
            if (binaryItem.second)
                version->binaries.insert(std::move(binaryItem));
        } else if (localName == String::AutoType){
            version->autoType = parse<Database::Version::AutoType>(reader);
        } else {
            return false;
        }
        return true;

    }

    inline Database::Version::Ptr takeResult(){
        if (customIcon != Uuid::nil()){
            for (const CustomIcon::Ptr& icon: meta.customIcons){
                if(icon->uuid() == customIcon){
                    version->icon = Icon(icon);
                    return std::move(version);
                }
            }
        }

        version->icon = Icon(standardIcon);
        return std::move(version);
    }

    static void writeOld(XmlWriter& writer, const Database::Version* data){
        if (data->parent())
            writer.writeElement(String::Uuid, data->parent()->uuid());
        if (data->icon.type() == Icon::Type::Custom){
            writer.writeElement(String::Icon, int(StandardIcon::Key));
            writer.writeElement(String::CustomIconID, data->icon.custom()->uuid());
        }else if (data->icon.type() == Icon::Type::Standard){
            writer.writeElement(String::Icon, int(data->icon.standard()));
        }else{
            writer.writeElement(String::Icon, int(StandardIcon::Key));
        }
        writer.writeElement(String::FgColor, data->fgColor);
        writer.writeElement(String::BgColor, data->bgColor);
        writer.writeElement(String::OverrideUrl, data->overrideUrl);
        writer.writeElement<Tags>(String::Tags, data->tags);
        writer.writeElement(String::Times, data->times);

        for (const std::pair<std::string, XorredBuffer>& item: data->strings){
            writer.writeElement<StringTag>(String::String, item);
        }
        for(const std::pair<std::string, std::shared_ptr<SafeVector<uint8_t>>>& item: data->binaries){
            writer.writeElement<Database::Version::Binary>(String::Binary, item);
        }

        writer.writeElement<Database::Version::AutoType>(String::AutoType, data->autoType);
    }


};

template <>
class Parser<std::vector<Database::Version::Ptr>>: public VectorTagParser<Parser<std::vector<Database::Version::Ptr>>, Database::Version::Ptr, Database::Version, const Database::Meta&, Database::Entry*>{
public:
    using VectorTagParser::VectorTagParser;

    static constexpr const char* itemTagName = String::Entry;

};

template <>
class Parser<Database::Entry>: public TagParser<Parser<Database::Entry>, Database::Entry::Ptr>{
private:
    const Database::Meta& meta;
    Database::Entry::Ptr entry;
    Parser<Database::Version> currentVersionParser;
public:
    typedef const Database::Entry* WrittenType;

    inline Parser(const Database::Meta& meta, Database::Group* group)
        :meta(meta),
          entry(new Database::Entry(group)),
          currentVersionParser(meta, entry.get())
    {}

    bool tag(XmlReader& reader){

        std::string localName = reader.localName();
        if (localName == String::Uuid){
            entry->fuuid = parse<Uuid>(reader);
        }else if (localName == String::History){
            std::vector<Database::Version::Ptr> tmp = parse<std::vector<Database::Version::Ptr>>(reader, meta, entry.get());
            entry->fversions.insert(entry->fversions.end(), std::make_move_iterator(tmp.begin()), std::make_move_iterator(tmp.end()));
        } else{
            return currentVersionParser.tag(reader, localName);
        }
        return true;

    }

    inline Database::Entry::Ptr takeResult(){
        entry->fversions.push_back(currentVersionParser.takeResult());
        return std::move(entry);
    }

    static void writeOld(XmlWriter& writer, const Database::Entry* data){
        assert(data->fversions.size() > 0);
        std::vector<Database::Version::Ptr>::const_iterator last = data->fversions.end()-1;
        writer.write<Database::Version>(last->get());
        writer.writeStartElement(String::History);
        for (std::vector<Database::Version::Ptr>::const_iterator I = data->fversions.begin(); I!= last; ++I){
            writer.writeElement<Database::Version>(String::Entry, I->get());
        }
        writer.writeEndElement();
    }


};

template <>
class Parser<Database::Group>: public TagParser<Parser<Database::Group>, Database::Group::Ptr>{
private:
    const Database::Meta& meta;
    Database::Group::Ptr data;
    Uuid customIcon;
    StandardIcon standardIcon;
    bool haveUuid;
public:

    typedef const Database::Group* WrittenType;

    inline Parser(const Database::Meta& meta, Database* database)
        :meta(meta),
          data(new Database::Group(database)),
          customIcon(Uuid::nil()),
          standardIcon(StandardIcon::Folder),
          haveUuid(false)
    {}

    inline Parser(const Database::Meta& meta, Database::Group* parent)
        :meta(meta),
          data(new Database::Group(parent)),
          customIcon(Uuid::nil()),
          standardIcon(StandardIcon::Folder)
    {}

    bool tag(XmlReader& reader){

        std::string localName = reader.localName();
        if (localName == String::Uuid){
            data->fuuid = parse<Uuid>(reader);
            haveUuid = true;
        } else if (localName == String::Name){
            data->fproperties->name = parse<std::string>(reader);
        } else if (localName == String::Notes){
            data->fproperties->notes = parse<std::string>(reader);
        } else if (localName == String::Icon){
            standardIcon = StandardIcon(parse<int>(reader));
        } else if (localName == String::CustomIconID){
            customIcon = parse<Uuid>(reader);
        } else if (localName == String::Times){
            data->fproperties->times = parse<Times>(reader);
        } else if (localName == String::IsExpanded){
            data->fproperties->isExpanded = parse<bool>(reader);
        } else if (localName == String::GroupDefaultAutoTypeSeq){
            data->fproperties->defaultAutoTypeSequence = parse<std::string>(reader);
        } else if (localName == String::EnableAutoType){
            data->fproperties->enableAutoType = parse<bool>(reader);
        } else if (localName == String::EnableSearching){
            data->fproperties->enableSearching = parse<bool>(reader);
        } else if (localName == String::LastTopVisibleEntry){
            data->fproperties->lastTopVisibleEntry = parse<Uuid>(reader);
        } else if (localName == String::Group){
            data->fgroups.push_back(parse<Database::Group>(reader, meta, data.get()));
        } else if (localName == String::Entry){
            data->fentries.push_back(parse<Database::Entry>(reader, meta, data.get()));
        } else {
            return false;
        }
        return true;

    }

    inline Database::Group::Ptr takeResult(){
        if (!haveUuid)
            data->fuuid = Uuid::generate();

        if (customIcon != Uuid::nil()){
            for (const CustomIcon::Ptr& icon: meta.customIcons){
                if(icon->uuid() == customIcon){
                    data->fproperties->icon = Icon(icon);
                    return std::move(data);
                }
            }
        }

        data->fproperties->icon = Icon(standardIcon);
        return std::move(data);
    }

    static void writeOld(XmlWriter& writer, const Database::Group* data){
        writer.writeElement(String::Uuid, data->fuuid);
        writer.writeElement(String::Name, data->fproperties->name );
        writer.writeElement(String::Notes, data->fproperties->notes );

        if (data->fproperties->icon.type() == Icon::Type::Custom){
            writer.writeElement(String::Icon, int(StandardIcon::Folder));
            writer.writeElement(String::CustomIconID, data->fproperties->icon.custom()->uuid());
        }else if (data->fproperties->icon.type() == Icon::Type::Standard){
            writer.writeElement(String::Icon, int(data->fproperties->icon.standard()));
        }else{
            writer.writeElement(String::Icon, int(StandardIcon::Folder));
        }
        writer.writeElement<Times>(String::Times, data->fproperties->times);
        writer.writeElement(String::IsExpanded, data->fproperties->isExpanded);
        writer.writeElement(String::GroupDefaultAutoTypeSeq, data->fproperties->defaultAutoTypeSequence);
        writer.writeElement(String::EnableAutoType, data->fproperties->enableAutoType);
        writer.writeElement(String::EnableSearching, data->fproperties->enableSearching);
        writer.writeElement(String::LastTopVisibleEntry, data->fproperties->lastTopVisibleEntry);
        for (const Database::Group::Ptr& item: data->fgroups){
            writer.writeElement<Database::Group>(String::Group, item.get());
        }
        for (const Database::Entry::Ptr& item: data->fentries){
            writer.writeElement<Database::Entry>(String::Entry, item.get());
        }
    }


};

template <>
class Parser<std::pair<Uuid, time_t>>: public TagParser<Parser<std::pair<Uuid, time_t>>, std::pair<Uuid, time_t>>{
private:
    Uuid uuid;
    std::time_t deletionTime;
public:
    inline Parser() noexcept
        :uuid(Uuid::nil()),
          deletionTime(static_cast<std::time_t>(-1)) // ToDo: is this portable?
    {}

    bool tag(XmlReader& reader){

        std::string localName = reader.localName();
        if (localName == String::Uuid){
            uuid = parse<Uuid>(reader);
        }else if (localName == String::DeletionTime){
            deletionTime = parse<Time>(reader);
        } else {
            return false;
        }
        return true;

    }

    inline std::pair<Uuid, time_t> takeResult(){
        return std::pair<Uuid, time_t>(std::move(uuid), std::move(deletionTime));
    }

    static void writeOld(XmlWriter& writer, const std::pair<Uuid, time_t>& data){
        writer.writeElement(String::Uuid, data.first);
        writer.writeElement<Time>(String::DeletionTime, data.second);
    }


};

template <>
class Parser<std::map<Uuid, time_t>>: public TagParser<Parser<std::map<Uuid, time_t>>, std::map<Uuid, time_t>>{
public:
    static constexpr const char* itemTagName = String::DeletedObject;

    bool tag(XmlReader& reader){
        std::string localName = reader.localName();
        if (localName == Parser::itemTagName){
            data.emplace(parse<std::pair<Uuid, time_t>>(reader));
        }else{
            return false;
        }
        return true;
    }

    inline std::map<Uuid, time_t> takeResult(){
        return std::move(data);
    }

    static void writeOld(XmlWriter& writer, const std::map<Uuid, time_t>& data){
        for (const std::pair<Uuid, time_t>& item: data){
            writer.writeElement(String::DeletedObject, item);
        }
    }

private:

    std::map<Uuid, time_t> data;
};

class RootTag;

template <>
class Parser<RootTag>: public TagParser<Parser<RootTag>, std::pair<Database::Group::Ptr, std::map<Uuid, time_t>>>{
private:
    const Database::Meta& meta;
    Database* fdatabase;
    Database::Group::Ptr rootGroup;
    std::map<Uuid, time_t> deletedObjects;
public:
    typedef std::pair<const Database::Group*, const std::map<Uuid, time_t>&> WrittenType;

    inline Parser(const Database::Meta& meta, Database* database) noexcept
        :meta(meta),
          fdatabase(database)
    {}

    bool tag(XmlReader& reader){

        std::string localName = reader.localName();
        if (localName == String::Group){
            rootGroup = parse<Database::Group>(reader, meta, fdatabase);
        } else if (localName == String::DeletedObjects){
            deletedObjects = parse<std::map<Uuid, time_t>>(reader);
        } else {
            return false;
        }
        return true;
    }

    inline std::pair<Database::Group::Ptr, std::map<Uuid, time_t>> takeResult(){
        if (!rootGroup)
            throw std::runtime_error("File contains no groups or entries.");
        return std::make_pair(std::move(rootGroup), std::move(deletedObjects));
    }

    static void writeOld(XmlWriter& writer, WrittenType data){
        writer.writeElement<Database::Group>(String::Group, data.first);
        writer.writeElement(String::DeletedObjects, data.second);
    }
};

template <>
class Parser<Database>: public TagParser<Parser<Database>, Database::Ptr>{
private:
    Database::Meta meta;
    Database::Ptr database;
    const Database::File::Settings& settings;
public:

    typedef const Database* WrittenType;

    Parser(const Database::File::Settings& settings)
        :database(new Database()),
          settings(settings)
    {}

    bool tag(XmlReader& reader){

        //ToDo: check if meta is populated before root maybe?
        std::string localName = reader.localName();
        if (localName == String::Meta){
            meta = parse<Database::Meta>(reader, settings);
        } else if (localName == String::Root){
            auto result = parse<RootTag>(reader, meta, database.get());
            database->froot = std::move(result.first);
            database->fdeletedObjects = std::move(result.second);
        } else {
            return false;
        }
        return true;

    }

    inline Database::Ptr takeResult(){
        database->frecycleBin = database->group(meta.recycleBinUUID);
        database->ftemplates = database->group(meta.templatesUUID);
        database->frecycleBinChanged = meta.recycleBinChanged;
        database->ftemplatesChanged = meta.templatesChanged;
        database->fsettings = std::move(meta.settings);
        database->customData = std::move(meta.customData);
        database->fcustomIcons = std::move(meta.customIcons);
        return std::move(database);
    }

    static void writeOld(XmlWriter& writer, const Database* data, const std::array<uint8_t, 32>& headerHash){
        // ToDo: header hash?
        writer.writeElement<Database::Meta>(String::Meta, data, headerHash);
        writer.writeElement<RootTag>(String::Root, std::pair<const Database::Group*, const std::map<Uuid, time_t>&>(data->froot.get(), data->fdeletedObjects));
    }


};

//ToDo: reader shoul probably verify header hash as well...
void XmlReaderLink::runThread(){

    try{
        current = InLink::read();
        if (!current)
            throw std::runtime_error("Unexpected end of stream.");
        currentPos = 0;

        XmlReader reader(this, XML_CHAR_ENCODING_UTF8, RandomStream::randomStream(fileSettings.crsAlgorithm, fprotectedStreamKey));

        reader.expectNext();
        xmlReaderTypes type = reader.nodeType();
        if (type != XML_READER_TYPE_ELEMENT || reader.localName() != String::DocNode)
            throw std::runtime_error("Bad stream format.");

        finishedPromise.set_value(parse<Database>(reader, fileSettings));
    }catch(...){
        finishedPromise.set_exception(std::current_exception());
        throw;
    }
}

void XmlWriterLink::runThread(){
        current = Pipeline::BufferPtr(new Pipeline::Buffer(Pipeline::Buffer::maxSize));
        currentPos = 0;
        XmlWriter writer(this, RandomStream::randomStream(database->settings().fileSettings.crsAlgorithm, fprotectedStreamKey));
        writer.setIndent(findent);
        writer.writeStartDocument();
        writer.writeElement<Database>(String::DocNode, database, fheaderHash);
        writer.writeEndDocument();
}

}

//--------------------------------------------------------------------------------

//static void writeHeader(SHA256_CTX* sha256, std::ostream* file, Internal::HeaderFieldId id, uint16_t size, const uint8_t* data){
//    using namespace Internal;
//    uint8_t hf[3];
//    hf[0] = uint8_t(id);
//    toLittleEndian(size, &hf[1]);
//    file->write(reinterpret_cast<const char*>(&hf[0]), 3);
//    file->write(reinterpret_cast<const char*>(data), size);
//    SHA256_Update(sha256, &hf[0], 3);
//    SHA256_Update(sha256, reinterpret_cast<const char*>(data), size);

//    //std::cout << "Writing header: " << uint32_t(hf.id) << ", size: " << size << ", content: ";
//    //outHex(std::cout, data, data+size);
//    //std::cout << std::endl;

//}

static void writeHeader(OSSL::Digest& d, std::ostream* file, Internal::HeaderFieldId id, uint16_t size, const uint8_t* data){
    using namespace Internal;
    uint8_t hf[3];
    hf[0] = uint8_t(id);
    toLittleEndian(size, &hf[1]);
    file->write(reinterpret_cast<const char*>(hf), 3);
    file->write(reinterpret_cast<const char*>(data), size);
    d.update(&hf[0], 3);
    d.update(data, size);
}

std::future<std::unique_ptr<std::ostream>> Database::saveToFile(std::unique_ptr<std::ostream> file, const CompositeKey& key) const{
    using namespace Internal;
    file->exceptions ( std::istream::failbit | std::istream::badbit | std::istream::eofbit );

    OSSL::Digest d(EVP_sha256());

    uint8_t h[3*4];
    toLittleEndian(FileSignature1, &h[0]);
    toLittleEndian(FileSignature2, &h[4]);
    toLittleEndian(FileVersion32, &h[8]);
    file->write(reinterpret_cast<char*>(h), 3*4);
    d.update(&h[0], 3*4);

    const File::Settings& settings = fsettings->fileSettings;

    Pipeline pipeline;
    std::unique_ptr<XmlWriterLink> writer;
    {
        SafeVector<uint8_t> data = OSSL::rand<SafeVector<uint8_t>>(128);
        std::array<uint8_t, 4> innerRandomStreamId;
        toLittleEndian(uint32_t(settings.crsAlgorithm), innerRandomStreamId.data());
        writer = std::unique_ptr<XmlWriterLink>(new XmlWriterLink(this, data));
        writeHeader(d, file.get(), HeaderFieldId::InnerRandomStreamID, innerRandomStreamId.size(), innerRandomStreamId.data());
        writeHeader(d, file.get(), HeaderFieldId::ProtectedStreamKey, data.size(), data.data());
    }

    if (settings.compress){
        pipeline.appendLink(std::unique_ptr<Pipeline::InOutLink>(new DeflateLink()));
        std::array<uint8_t, 4> compression;
        toLittleEndian(uint32_t(settings.compression), compression.data());
        writeHeader(d, file.get(), HeaderFieldId::CompressionFlags, 4, compression.data());
    }

    {
        std::array<uint8_t,32> initBytes = OSSL::rand<std::array<uint8_t,32>>();
        pipeline.appendLink(std::unique_ptr<Pipeline::InOutLink>(new HashStreamLink(initBytes)));
        writeHeader(d, file.get(), HeaderFieldId::StreamStartBytes, initBytes.size(), initBytes.data());
    }

    if (settings.encrypt){
        auto match = std::mismatch(settings.cipherId.begin(), settings.cipherId.end(), File::AES_CBC_256_UUID.begin());
        if (match != std::make_pair(settings.cipherId.end(), File::AES_CBC_256_UUID.end())){
            std::ostringstream s;
            s << "Unsupported cipher UUID: ";
            outHex(s, settings.cipherId);
            throw std::runtime_error(s.str());
        }


        // Figure out total size of necesary random data and dump it all at once.
        std::array<uint8_t,32> masterSeed = OSSL::rand<std::array<uint8_t,32>>();
        std::array<uint8_t,32> transformSeed = OSSL::rand<std::array<uint8_t,32>>();
        std::array<uint8_t,16> encryptionIV = OSSL::rand<std::array<uint8_t,16>>();


        // ToDo: some arrays here should be safe!!!

        OSSL::Digest keyHash(EVP_sha256());
        keyHash.update(masterSeed.data(), masterSeed.size());
        SafeVector<uint8_t> hash = key.getCompositeKey(transformSeed, settings.transformRounds);
        if (hash.size() != 32){
            std::ostringstream s;
            s << "Composed key has wrong size: " << hash.size() << "\nThis should not have happened.";
            throw std::runtime_error(s.str());
        }
        keyHash.update(hash);
        keyHash.final(hash);

        std::unique_ptr<EvpCipher> cipher(new EvpCipher());
        if (EVP_CipherInit(cipher->context(), EVP_aes_256_cbc(), hash.data(), encryptionIV.data(), 1) == 0)
            throw std::runtime_error("Error initializing AES256 CBC decryptor.");
        EVP_CIPHER_CTX_set_padding(cipher->context(), 1);
        pipeline.appendLink(std::unique_ptr<Pipeline::InOutLink>(std::move(cipher)));

        writeHeader(d, file.get(), HeaderFieldId::CipherID, settings.cipherId.size(), settings.cipherId.data());
        writeHeader(d, file.get(), HeaderFieldId::MasterSeed, masterSeed.size(), masterSeed.data());
        writeHeader(d, file.get(), HeaderFieldId::TransformSeed, transformSeed.size(), transformSeed.data());
        std::array<uint8_t, sizeof(settings.transformRounds)> transformRounds;
        toLittleEndian(settings.transformRounds, transformRounds.data());
        writeHeader(d, file.get(), HeaderFieldId::TransformRounds, transformRounds.size(), transformRounds.data());
        writeHeader(d, file.get(), HeaderFieldId::EncryptionIV, encryptionIV.size(), encryptionIV.data());
    }

    const std::array<uint8_t,4> endOfHeader = {0x0D, 0x0A, 0x0D, 0x0A};
    writeHeader(d, file.get(), HeaderFieldId::EndOfHeader, 4, endOfHeader.data());


    writer->setIndent(1);
    //SHA256_Final(writer->headerHash().data(), &headerHash);
    d.final(writer->headerHash());
    pipeline.setStart(std::move(writer));

    std::unique_ptr<OStreamLink> finish(new OStreamLink(std::move(file)));
    std::future<std::unique_ptr<std::ostream>> result = finish->getFuture();
    pipeline.setFinish(std::move(finish));



    pipeline.run();
    return result;
}

/*std::future<std::unique_ptr<std::ostream>> Database::saveToXmlFile(std::unique_ptr<std::ostream> file) const{
    using namespace Internal;

    Pipeline pipeline;
    std::unique_ptr<XmlWriterLink> writer(new XmlWriterLink(this, KdbxRandomStream::randomStream(KdbxRandomStream::Algorithm::Null, std::vector<uint8_t>()) ));
    writer->setIndent(1);
    pipeline.setStart(std::move(writer));

    std::unique_ptr<OStreamLink> finish(new OStreamLink(std::move(file)));
    std::future<std::unique_ptr<std::ostream>> result = finish->getFuture();
    pipeline.setFinish(std::move(finish));
    pipeline.run();
    return result;
}*/


// Settings: cipherId - uuid,
//           compressionFlags: CompressionAlgorithm,
//           encryptionRounds: uint32_t,

static void checkHeader(std::istream* file){
    using namespace Internal;
    uint8_t h[3*4];
    file->read(reinterpret_cast<char*>(&h[0]), 3*4);
    uint32_t sig1 = fromLittleEndian<uint32_t>(&h[0]);
    uint32_t sig2 = fromLittleEndian<uint32_t>(&h[4]);
    uint32_t version = fromLittleEndian<uint32_t>(&h[8]);

    if (sig1 == FileSignatureOld1 && sig2 == FileSignatureOld2)
        throw std::runtime_error("File in KeePass 1.x format.");

    if ((sig1 != FileSignature1 || sig2 != FileSignature2) &&
            (sig1 != FileSignaturePreRelease1 || sig2 != FileSignaturePreRelease2))
        throw std::runtime_error("File has an invalid signature.");

    if ((version & FileVersionCriticalMask) > (FileVersion32 & FileVersionCriticalMask))
        throw std::runtime_error("File version is newer than supported.");
}

Database::File Database::loadFromFile(std::unique_ptr<std::istream> file){

    using namespace Internal;
    file->exceptions ( std::istream::failbit | std::istream::badbit | std::istream::eofbit );

    checkHeader(file.get());

    File result;



    uint8_t hf[3];
    std::bitset<int(HeaderFieldId::Max)> haveField;

    do{
        file->read(reinterpret_cast<char*>(&hf[0]), 3);
        uint16_t size = fromLittleEndian<uint16_t>(&hf[1]);
        std::vector<uint8_t> data(size);
        file->read(reinterpret_cast<char*>(data.data()), size);

        std::cout << "Header: " << uint32_t(hf[0]) << ", size: " << size << ", content: ";
        outHex(std::cout, data);
        std::cout << std::endl;

        if (HeaderFieldId(hf[0]) >= HeaderFieldId::Max){
            std::cerr << "Warning: unknown header field id: " << uint32_t(hf[0]) << '\n';
            continue;
        }

        haveField.set(uint32_t(hf[0]));


        switch (HeaderFieldId(hf[0])){
        case HeaderFieldId::EndOfHeader:
            break;

        default:
        case HeaderFieldId::Comment:
            break;

        case HeaderFieldId::CipherID:
            if (size != 16) throw std::runtime_error("Invalid UUID given as CipherID.");
            result.settings.encrypt = true;
            std::copy(data.begin(), data.end(), result.settings.cipherId.begin());
            break;

        case HeaderFieldId::CompressionFlags:
            if (size != 4)
                throw std::runtime_error("Compression flags header invalid.");
            result.settings.compress = true;
            result.settings.compression = File::CompressionAlgorithm(fromLittleEndian<uint32_t>(data.data()));
            break;

        case HeaderFieldId::MasterSeed:
            if (size!=32)
                throw std::runtime_error("Master seed header invalid.");
            std::copy(data.begin(), data.end(), result.masterSeed.begin());
            break;

        case HeaderFieldId::TransformSeed:
            if (data.size()!=32)
                throw std::runtime_error("Transform seed header invalid.");
            std::copy(data.begin(), data.end(), result.transformSeed.begin());
            break;

        case HeaderFieldId::TransformRounds:
            if (data.size() != 8)
                throw std::runtime_error("Transform rounds header invalid.");
            result.settings.transformRounds = fromLittleEndian<uint64_t>(data.data());
            break;

        case HeaderFieldId::EncryptionIV:
            if (data.size() != 16)
                throw std::runtime_error("Encryption IV header invalid.");
            std::copy(data.begin(), data.end(), result.encryptionIV.begin());
            break;

        case HeaderFieldId::ProtectedStreamKey:
            result.protectedStreamKey.resize(data.size());
            std::copy(data.begin(), data.end(), result.protectedStreamKey.begin());
            break;

        case HeaderFieldId::StreamStartBytes:
            if (data.size()!=32)
                throw std::runtime_error("Stream start bytes header invalid.");
            std::copy(data.begin(), data.end(), result.streamStartBytes.begin());
            break;

        case HeaderFieldId::InnerRandomStreamID:
            if (data.size() != 4)
                throw std::runtime_error("InnerRandomStreamID header invalid.");
            result.settings.crsAlgorithm = RandomStream::Algorithm(fromLittleEndian<uint32_t>(data.data()));
            break;
        }

    }while (HeaderFieldId(hf[0]) != HeaderFieldId::EndOfHeader);

    std::cout << "Header: " << uint32_t(hf[0]) << ", size: " << fromLittleEndian<uint16_t>(&hf[1]) << ", no content.\n";

    // ToDo: describe those headers better and decide if checks are necesary.
    if (!haveField.test(int(HeaderFieldId::StreamStartBytes)) ||
            !haveField.test(int(HeaderFieldId::ProtectedStreamKey)) ||
            !haveField.test(int(HeaderFieldId::InnerRandomStreamID)))
        throw std::runtime_error("Necesary header fields missing.");

    if (result.settings.encrypt){
        if (!haveField.test(int(HeaderFieldId::MasterSeed)) ||
                !haveField.test(int(HeaderFieldId::TransformSeed)) ||
                !haveField.test(int(HeaderFieldId::EncryptionIV)) ||
                !haveField.test(int(HeaderFieldId::TransformRounds)))
            throw std::runtime_error("Necesary header fields missing.");

        auto match = std::mismatch(result.settings.cipherId.begin(), result.settings.cipherId.end(), File::AES_CBC_256_UUID.begin());
        if (match != std::make_pair(result.settings.cipherId.end(), File::AES_CBC_256_UUID.end())){
            std::ostringstream s;
            s << "Unsupported cipher UUID: ";
            outHex(s, result.settings.cipherId);
            throw std::runtime_error(s.str());
        }
    }

    result.ffile = std::move(file);
    return result;

}


bool Database::File::needsKey(){
    return settings.encrypt;
}

std::future<Database::Ptr> Database::File::getDatabase(const CompositeKey& key){

    using namespace Internal;

    //KdbxRandomStream::Ptr randomStream(KdbxRandomStream::randomStream(KdbxRandomStream::Algorithm(settings.crsAlgorithm), protectedStreamKey));
    std::unique_ptr<XmlReaderLink> finish(new XmlReaderLink(settings, protectedStreamKey));
    std::future<Database::Ptr> result(finish->getFuture());

    Pipeline pipeline;
    pipeline.setStart(std::unique_ptr<Pipeline::OutLink>(new IStreamLink(std::move(ffile))));
    ffile = std::unique_ptr<std::istream>();

    if (settings.encrypt){
        OSSL::Digest keyHash(EVP_sha256());
        keyHash.update(masterSeed);
        SafeVector<uint8_t> hash = key.getCompositeKey(transformSeed, settings.transformRounds);
        keyHash.update(hash);
        keyHash.final(hash);

        std::unique_ptr<EvpCipher> cipher(new EvpCipher());
        if (EVP_CipherInit(cipher->context(), EVP_aes_256_cbc(), hash.data(), encryptionIV.data(), 0) == 0)
            throw std::runtime_error("Error initializing AES256 CBC decryptor.");
        EVP_CIPHER_CTX_set_padding(cipher->context(), 1);
        pipeline.appendLink(std::unique_ptr<Pipeline::InOutLink>(std::move(cipher)));
    }

    pipeline.appendLink(std::unique_ptr<Pipeline::InOutLink>(new UnhashStreamLink(streamStartBytes, true)));

    if (settings.compress){
        switch(settings.compression){
        default:
            throw std::runtime_error("Unknown copression algorythm.");
        case CompressionAlgorithm::GZip:
            pipeline.appendLink(std::unique_ptr<Pipeline::InOutLink>(new InflateLink()));
        case CompressionAlgorithm::None:;
        }
    }

    //pipeline.appendLink(std::unique_ptr<Pipeline::InOutLink>(new OStreamTeeLink("outfile.xml")));
    pipeline.setFinish(std::move(finish));
    pipeline.run();

    return result;

}

std::future<Database::Ptr> Database::File::getDatabase(){
    using namespace Internal;

    std::unique_ptr<XmlReaderLink> finish(new XmlReaderLink(settings, protectedStreamKey));
    std::future<Database::Ptr> result(finish->getFuture());

    Pipeline pipeline;
    pipeline.setStart(std::unique_ptr<Pipeline::OutLink>(new IStreamLink(std::move(ffile))));
    ffile = std::unique_ptr<std::istream>();

    if (settings.encrypt){
        throw std::runtime_error("Database is compressed but no keys were provided.");
    }

    pipeline.appendLink(std::unique_ptr<Pipeline::InOutLink>(new UnhashStreamLink(streamStartBytes, true)));

    if (settings.compress){
        switch(settings.compression){
        default:
            throw std::runtime_error("Unknown copression algorythm.");
        case CompressionAlgorithm::GZip:
            pipeline.appendLink(std::unique_ptr<Pipeline::InOutLink>(new InflateLink()));
        case CompressionAlgorithm::None:;
        }
    }

    pipeline.setFinish(std::move(finish));
    pipeline.run();

    return result;
}

void Database::init() noexcept{
    xmlInitParser();
}

} //namespace Kdbx

//-------------------------------------------------------------------------------------------------

