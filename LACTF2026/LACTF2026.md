# LACTF 2026

> A/N: I started writing these write ups, but I never got around to finish writing up all the challenges. These are two of the challenge solves I'm most proud of.

## rev/flag-finder

### The problem

- the website is a big box of what is basically checkboxes
- a script takes the checkboxes and turns it into a string of `.` and `#` , left to right, top to bottom
- the string is then compared to a massive regex

### Figuring it out

- doing some analysis on the regex splits the regex into two halves
  - first half defines columns with blocks of `#` separated by 1 or more `.`s
  - similarly, second half defines rows with blocks of `#` separated by 1 or more `.`s
  - prior general puzzle experience tells me this feels very similar to a "nonogram", which similarly uses a grid that must be filled to the specification of clues for columns/rows that define groups.
- therefore, the goal is to extract these clues from the regex, then solve the nonogram

### Solving it

- first, extracting the clues from the regex
  - since the regex is so long, its sensible to split it up into parts, throw the important bits an array, then use regex tools to parse the individual bits
  - the rows came out first, since they weren't nested and were more straight forward to parse. each row was separated by another expression that made sure each row expression only applied to that specific set of characters in the string.
  - the columns were a little trickier, as they took the form odd nested lookaheads. this is because since the grid is just one long string, there isn't a direct sense of "columns" compared to "rows". extracting the clues from this required additional parsing with `re.compile` and `re.search`. I admittedly used ChatGPT to help generate these patterns.
    - additionally, the columns are listed in a random order in the regex, so some sorting was performed to get everything in order
  - In the end I was left with two files, listing the nonogram-style number clues for the rows and columns respectively. 
- second, actually solving the nonogram
  - I at first tried using a nonogram solver program I found on [Rosetta Code](https://rosettacode.org/wiki/Nonogram_solver), but since the grid is so massive (19 x 101) and there were so many clues, the program would take an extremely long time to find a solution using it's brute force method.
  - Instead I decided to manually use the clues to solve it.
    - first, instead of having a list of very long row clues, I adjusted my program to create a file that created the corrected groupings automatically with Unicode full blocks and `.`s.
    - I then began to partially resolve each column using classing nonogram soling strategies
    - the grid very clearly aligns itself into 3 text lines, and the column clues clearly show everything falls into a width of 3 columns. Some experimentation with trying to spell out the flag prefix provided fruitful, leading to the assumption that the solution was simply going to spell out the flag
    - at this point it was just a matter of trying to figure out the letters and how they align with the clue. as more letters were created, this process became easier since the previous letters and their patterns can be reused into a consistent font.

In the end, the assumption was correct, and the grid spelled out the flag:

`
lactf{Wh47_d0_y0u_637_wh3n_y0u_cr055_4_r363x_4nd_4_n0n06r4m?_4_r363x06r4m!}
`
Side note: I didn't bother with checking my work by plugging it into the original website, but after the challenge I did so. This is what it looks like:

![Image](<attachments/Pasted image 20260208205434.png>)

Not sure what I was expecting to be frank.

### Retrospective

I still don't really like dealing with regex, so honestly I'm glad AI can be such a useful tool in parsing it. I'm quite impressed with the rest of the challenge as well. Not only is simply parsing the regex a challenge, but also understanding what the regex does is another. I can't believe that Nonogram rules are able to be implemented through these insane regex rules.

## crypto/ttyspin

holy crap its tetris

### The problem

- `ssh` into the remote auto runs a python program for a game of Tetris
- in addition to the game itself, the program asks for a username and a save code that can be used to recover in-progress games. if a save code is put in, a check sum is also asked for. 
- while playing the game, at any time `e` can be pressed to export the game, which produces a game code and its check sum.
- a brief look into the provided source code clearly identifies a winning board. a little extra digging will reveal the numerical representation of each piece type/color, including `0`s for empty space. following the Tetris guiding, this is what it looks like:

![Image](<attachments/Pasted image 20260208082903.png>)

- even without in-depth Tetris knowledge, obtaining this winning board looks utterly insane. However, someone with better understanding of Tetris and its mechanics can easily identify the sheer impossibility of this shape.
  - This shape is called the "Reverse Secret Grade". while difficult, the general zig-zag shape is possible.
  - the impossible part about this specific board are the required pieces that take up each filled space of the board, specifically the yellow piece. Since the yellow piece is a square, no matter how you rotate it, it is impossible to only get 1 yellow cell by itself in a row.
- Therefore, there must be some other way - the crypto part

### Figuring it out

- with actually playing the game out of the question - the only other logical location for an exploit, especially a crypto one, would be the importing and exporting function.
- This is how the import/export works
  - username is tracked, must be `len(username) <= 32`
  - save code is a `base64` encoding of plaintext representing the state of the board, split into 5 fields separated by `|`:
    - `current|hold|nexts|queue|board`
  - reading more of the code implies certain qualities of these fields:
    - `current`: the piece that they player actively controls - always 1 character
    - `hold`: the held piece - can be 1 or 0 characters
    - `nexts`: the visual next queue - always 4 characters
    - `queue`: the "bag" (Tetris concept) - between 0 and 7 characters
    - `board`: a linear representation of the 2d playing field, using spaces for empty cells and the corresponding letter for the filled cells - must be 200 or more characters (the "or more" part will be important later)
  - finally, the check sum is created by taking a secret of length 40, the username, and the save code, concatenating and stripping the concatenation, feeding it to `sha256`, and getting the `hexdigest()` of that.
- With this in mind, a closer look at how the save code is a direct, plaintext representation of the board state, it is pretty clear the goal is to create a modified save code that immediately puts us at the winning board state.

### Overcoming the challenges

**the first challenge**: the check sum: how can change the save code when we don't have a check sum?

- googling vulnerabilities, we realize that the hashing algorithm `sha256` is vulnerable to length extension attacks.
- This is why `board`'s ability to take more than 200 characters without failing is important, this means we can do length extension to however long we want
- the way length extension works is that if you know the length of the secret, an initial message, and the resulting hash with the combination of the secret and the initial message, you concatenate padding + any message you want to append.
  - the technical way this works is that since `sha256` does things in blocks of 512, adding padding in addition to the appended message allows for the state of the algorithm to be predictable, effectively continuing where it left off, allowing a new valid hash to be generated for the padded message
- **solution attempt 1**:
  - get a save code + check sum without a board, so that our winning board can easily be appended to it
    - to get one without a board, take advantage of the `strip()`, an empty board means a board with all spaces, which means all the spaces get stripped
    - this can be done by performing an "all clear" in the game. Note: you cannot immediately export at game start, so you have to do an "all clear"
  - use a library or something to generate the "forced" save code and its valid hash
    - don't forget to separate out the username from the resulting code, so it doesn't appear twice
  - use the same username, the new game code, and the new hash to try to get it to import

**the second challenge:** `.decode()`: what do you mean I can't have padding?

- trying the first solution fails. this is because the padding used by the length extensions isn't decodable with `utf-8`
- since our padding is set between the end of the last `|` and our winning board. there is no way to avoid this error being triggered.
  - does this mean length extension doesn't work?
  - aside: this is where I got stuck for quite a while trying to brainstorm, theory craft, and search for other methods of exploitation it took quite a while to get to:
- the key insight: username and save code are simply concatenated together.
  - this means that moving some characters from the beginning/end of one to the other will not change the resulting concatenated result
  - the program does not `.decode()` username - this means the error won't appear if padding is moved to the username.
- **solution attempt 2:**
  - since the padding, along with the rest of the save code, is going into the username, adjust the appended message to include the entire save code instead of just the winning table
  - rerun the algorithm to get new padding and check sum
  - instead of just separating out the username, separate out everything up to the last padding character
  - try the import

**the third challenge:** `len(username) <= 32`: dang, that username with all that padding is way too long

- how to shorten padding? googling says the length of the padding depends on the length of the initial message, including the length of the secret. this length should be `length % 64 = 55` or a little less to absolutely minimize the number of characters
- a single character username with just a single 4 line "all-clear" results in a message length of 56 - worst case scenario. obvious going forward to reach the right mod length is counter-intuitive, so we need to shed a character or two somehow. here are two solutions:
  - don't use hold - this would save exactly 1 character. this is extremely RNG dependent though, as without hold, doing a perfect clear right off the bat has dramatically lower odds.
  - bag manipulation - it takes 10 pieces to do a perfect clear. 6 pieces are already visible thanks to the `current`, `hold`, and `nexts` pieces. this leaves 5 pieces in the `queue` bag. to make 21 pieces total, a multiple of 7. using pieces reduces the amount of pieces in the `queue` bag until it is empty, an easier way to reduce the character count.
    - there are probably a few ways, but I chose to simply chose to PC again, `20 + 6 + 2 = 28`, leaving 2 in the bag and reducing our message length by 3, now under the limit. 
    - note: ideally I should have used a username 3 characters long, but a simple math error caused me to use one with 2 instead. luckily the 32 character limit isn't quite that restrictive
  - The intended solution? just use an empty username. *facepalm* That means only requiring a (Perfect Clear Opener) PCO. The other methods above still work however.
- There is one final hurdle, due to the way the terminal works, pasting straight bytes just doesn't work. the `\x80` and `\x00`s that make up the padding are interpreted literally. This wasn't an issue when the padding was part of the save code - it was encoded into the `base64`.
  - this simply meant copy pasting via terminal wasn't going to work, and the answer would have to be directly inserted into the `ssh` program
- **solution attempt 3:**
  - create a new initial save code and corresponding check sum with a very short (1-3 characters long) username and perfect clear with less than 5 pieces left in the bag (i did 2 perfect clears back to back)
  - once again do the steps of attempt 2, rerunning with the new initial values.
  - instead of printed directly to `stdout`, write to a binary file instead. remember to also write `\n` characters after each prompt so it isn't one big message/is split into multiple lines of input
    - keep it in the binary representation avoids the issue of literal interpretation from copy-pasting
  - pipe the binary file into the `ssh` program. this may be finicky due to some quicks with whatever you're using for example:
    - simply using `cat` doesn't work (at least on PowerShell)
    - PowerShell in general tends to do some weird things to the binary output it makes, so I switched to command prompt
    - regular piping with the `-T` flag on `ssh` doesn't work, since the the `curses` library used to display the game breaks without an actual (pseudo-)terminal and TTY
    - what ended up working was using the `type` command, `cmd`'s way of displaying text from a file, and using the `-tt` flag on `ssh` to force the pseudo-terminal and TTY

And thus outputs the flag:
`
lactf{T3rM1n4L_g4mE5_R_a_Pa1N_2e075ab9ae6ae098}
`

### Retrospective

Honestly I don't really know what to say here. This is such a niche clashing of interests on such a difficult problem to solve - I don't think I would have had the motivation to complete the challenge if it weren't for the theming. I do find it extremely funny that this challenge required players to perform a PCO in order to complete it.
