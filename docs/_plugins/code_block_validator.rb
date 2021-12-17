# Description : This plugin checks code blocks created using `or``` 
# in their markdown state for special characters that can cause problem in terminal.
# Authour : Reza R <54559947+frozenprocess@users.noreply.github.com>
#####
Jekyll::Hooks.register :pages, :pre_render do |post|
    # do nothing if url indicates legal folder
    if !post.path.match(/\/legal\//)
        occurrences = []
        # Check post content and extract code blocks
        post.content.scan(/(?:[`]{3}|(?<!`)[`](?!`))(.*?)(?:[`]{3}|(?<!`)[`](?!`))/m){ |match|
            # Check all matched cases
            match.each do |block|
                # convert each character to an array of Decimal numbers
                # and iterate each character.
                block.codepoints.each_with_index do |b_chr, idx|
                    # \n (9) and \t (10) are exceptions for this block
                    if ( b_chr < 32 && ![9,10].include?(b_chr) ) || b_chr > 126
                        occurrences.append({'code' => block, 'idx' => idx})
                    end 
                end
            end
        }
        # were there any special characters?
        if occurrences.length > 0
            occurrences.each do |sentence|
                # printing line to user
                print(sentence['code'][sentence['idx']-10..sentence['idx']+10].strip)
                # printing position of the character
                print("\n"+" "*10 + "^~~~~~~~~~~~\n")
            end 
            # Stop compiling 
            raise "\n Unexpected character in codeblock detected: #{post.path}"
        end 
    end
end
