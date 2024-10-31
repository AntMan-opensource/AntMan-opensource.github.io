

namespace juce {

static File createTempFile (const File& parentDirectory, String name, const String& suffix, int optionFlags)
{
    if ((optionFlags & TemporaryFile::useHiddenFile) != 0)
        name = "." + name;

    return parentDirectory.getNonexistentChildFile (name, suffix, (optionFlags & TemporaryFile::putNumbersInBrackets) != 0);
}

TemporaryFile::TemporaryFile (const String& suffix, const int optionFlags)
    : temporaryFile (createTempFile (File::getSpecialLocation (File::tempDirectory), "temp_" + String::toHexString (Random::getSystemRandom().nextInt()), suffix, optionFlags)), targetFile()


{
}

TemporaryFile::TemporaryFile (const File& target, const int optionFlags)
    : temporaryFile (createTempFile (target.getParentDirectory(), target.getFileNameWithoutExtension()
                                       + "_temp" + String::toHexString (Random::getSystemRandom().nextInt()), target.getFileExtension(), optionFlags)), targetFile (target)

{
    
    jassert (targetFile != File());
}

TemporaryFile::TemporaryFile (const File& target, const File& temporary)
    : temporaryFile (temporary), targetFile (target)
{
}

TemporaryFile::~TemporaryFile()
{
    if (! deleteTemporaryFile())
    {
        
        jassertfalse;
    }
}


bool TemporaryFile::overwriteTargetFileWithTemporary() const {
    
    
    jassert (targetFile != File());

    if (temporaryFile.exists())
    {
        
        for (int i = 5; --i >= 0;)
        {
            if (temporaryFile.replaceFileIn (targetFile))
                return true;

            Thread::sleep (100);
        }
    }
    else {
        
        
        jassertfalse;
    }

    return false;
}

bool TemporaryFile::deleteTemporaryFile() const {
    
    for (int i = 5; --i >= 0;)
    {
        if (temporaryFile.deleteFile())
            return true;

        Thread::sleep (50);
    }

    return false;
}

} 
