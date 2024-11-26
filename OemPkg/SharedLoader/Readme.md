## Decisions


CoreLoadImage
    - Creates a private internal handle that does not provide the caller with easy access to the PE32 information
    - for this reason we'll be forced to handle this ourselves