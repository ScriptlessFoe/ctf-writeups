# LA CTF 2025 Writeups

Hey y'all, I'm ScriptlessFoe, a freshman at UTK and a member of [HackUTK](https://hackutk.org/)! I would like to share my solutions to the two challenges **(rev/nine-solves and rev/crypt-of-the-necropuzzler)** I managed to solve independently.

I'm very happy to have finished my very first CTF, and  with this writeup, I aim to give a slightly different perspective on solving these challenges through the lens of a first-timer. I hope to participate in more CTFs in the future and perform better next year!

- [LA CTF 2025 Writeups](#la-ctf-2025-writeups)
  - [rev/nine-solves](#revnine-solves)
    - [Full Code Breakdown](#full-code-breakdown)
    - [Program Analysis](#program-analysis)
    - [Tl;dr](#tldr)
    - [Solution](#solution)
  - [rev/crypt-of-the-necropuzzler](#revcrypt-of-the-necropuzzler)
    - [Full Code Breakdown](#full-code-breakdown-1)
    - [Tl;dr](#tldr-1)
    - [Solution](#solution-1)
      - [Extra Note](#extra-note)
  - [Conclusion](#conclusion)


--verbose lol

## rev/nine-solves

![image](https://hackmd.io/_uploads/HyjsyaLYJg.png)

Taking a look at the challenge description, it gives little information other than a netcat and an executable that presumably is an example exe of the netcat. With nothing else to look at, I fire up my Kali Linux VM and get to work.

First thing to try of course, is running the netcat and seeing what happens:

![image](https://hackmd.io/_uploads/B1lpG6UFkl.png)\
Looks like it wants some kind of password.

![image](https://hackmd.io/_uploads/rJKzmaIKJl.png)\
The random guess, of course, doesn't work. Sadly, the response from the failed guess doesn't give much information either. Other random password guesses result in the same `ACCESS DENIED` message.

From what I gleaned from watching a teammate solve `rev/patricks-paraflag`, the first thing I try to do is use `strings` to get more information about the program and see if there are any remnants of a flag in there.

![image](https://hackmd.io/_uploads/HkjySaLtye.png)\
Around the middle of the list of strings, I do find some hints of the flag (`Could not open flag.txt`), as well as the output strings for both entering the password and getting the password wrong. On a whim, I tried entering the string right under the `Please enter your access code:` string but that still resulted in failure. Without much else to go off of, I looked online for general reverse CTF tips.

I found [this](https://ctf101.org/reverse-engineering/what-are-decompilers/) handbook on doing CTFs and found the reverse section mentioning decompilers. Intrigued by the idea of reverting exes back to pseudocode, I decided to try [Binary Ninja](https://binary.ninja/free/) because it was free and has a cloud version that can decompile in browser (no downloading!).

Throwing the `nine-solves` exe (also called a binary so I've learned) into the decompiler greets us with this screen:

![image](https://hackmd.io/_uploads/Bk8fOT8FJx.png)\
As this is my first time using Binary Ninja, I take some time snooping around the interface, clicking around to test all the features. Eventually I set the language to pseudo C, changed the view to Linear Disassembly, and honed in on two functions mentioned in the sidebar.

### Full Code Breakdown

The first thing that comes to my attention is the `eigong()` function:

![image](https://hackmd.io/_uploads/rytxYa8KJl.png)\
Just by a quick glance, we can see there is an `fopen()` for a `"flag.txt"`. There's also the `"Could not open flag.txt"` string we found with the `string` command, so this function definitely has our flag in it.

Then we come to the `main()` function, which should have the main program in it:

![image](https://hackmd.io/_uploads/HygZcp8F1l.png)
![image](https://hackmd.io/_uploads/r1BEqaLKJg.png)
![image](https://hackmd.io/_uploads/S13LqaIYyx.png)\
And yup, there's the strings for asking and denying the password.

Looking at `main()` in the default flowchart view actually makes things a bit easier to parse:

![image](https://hackmd.io/_uploads/B1NJ2TUYyl.png)\
The program starts by asking for a password string, which it takes from `stdin`,
and stores it in an array `&buf`. It also initializes an int `rsi`, which we will
later see is an incrementor for the upcoming while loop.

![image](https://hackmd.io/_uploads/Hyps2T8Kke.png)\
Now inside the outer while loop, the start of the loop sets three new variables, `rax_1`, `rcx_1`, and `rdx_2` and does some logic on these variables:

- `rax_1` is set to value of the `rsi`th character of our string stored in `&buf` using pointer arithmetic. The if statement, when simplified, then checks if that character (represented by an ASCII number) is an actual ASCII character.
- `rcx_1` is similarly set to the `rsi`th value of a mysterious `&yi` array using more pointer arithmetic. The if statement then checks if that value is `0` or not.
- `rdx_2` is set to `0`, presumably another incrementor for the inner while loop coming up.

If `rax_1` isn't an ASCII character, or if `rcx_1` is 0, the while loop breaks and is sent here:

![image](https://hackmd.io/_uploads/rJ-5yAUtkl.png)\
This is the fail state of the program, so we want to avoid going here if possible. The 5 arrows pointing to this chunk of code does not seem to bode well.

![image](https://hackmd.io/_uploads/HyU8fRLFkg.png)\
We arrive at our inner while loop. We see the reappearance of several variables, so I will break this down quickly in pseudocode.

```!
repeat "rdx_2" times:
    if "rax_1" is even:
        divide "rax_1" by 2
    else:
        multiply "rax_1" by 3, then add 1
    if "rax_1" equals 1 before the end of the loop:
        go to fail state
```

This pattern of operations might already be familiar, but I'll save that for the analysis later on.

After the inner while loop:\
![image](https://hackmd.io/_uploads/Hyl3KRItkx.png)

There's one more check for `rax_1` which causing a fail state if it isn't equal to 1. This combined with the previous while loop means that `rax_1` must reach `1` after exactly `rdx_2` loops of the above while loop to be successful.

Finally, we increment `rsi` and check if it equals 6, and if it does, it performs one final check before returning our flag function!

### Program Analysis

The first thing of note is that last section with our flag function:

![image](https://hackmd.io/_uploads/rJ3po0UKJg.png)\
Given that we know that `rsi` is an incrementor that grabs the `rsi`th character of `&buf`, this means that `rsi` iterates through the input string that we give it. Seeing that it must equal `6` to get to our flag, **it is safe to assume that our password is 6 characters long.**

The next thing to notice is that inner while loop (pseudocode reproduced here):

```!
repeat "rdx_2" times:
    if "rax_1" is even:
        divide "rax_1" by 2
    else:
        multiply "rax_1" by 3, then add 1
    if "rax_1" equals 1 before the end of the loop:
        goto fail state
```

This process of dividing by 2 if even and multiplying by 3 and adding 1 if odd is actually a famous unsolved problem in mathematics called the "3x+1" conjecture, or more formally, the [Collatz conjecture](https://en.wikipedia.org/wiki/Collatz_conjecture). Knowing the all exact details of the conjecture is not important to solving the challenge, so read up at your own leisure.

One detail of this conjecture we can take note of is the number of steps for any given number to reach `1`. Given that `rax_1` must equal `1` after exactly `rdx_2` loops (or steps) of these operations, **`rdx_2` is the number of steps a given `rax_1` takes to reach `1` using this process.**

The last piece of the puzzle is that mysterious `&yi` array, who's values are used to define `rdx_2`. I struggled on this step given inexperience with Binary Ninja, but eventually I figure out that double clicking on the name sends me here:

![image](https://hackmd.io/_uploads/HyhSgyvFkx.png)\
Surprise surprise, it sends me straight to the values of the array. Taking note of the non-zero values of the array, we see 6 of them, reconfirming our previous assumption of the length of the password. **These values represent the number of steps it should take for each character (in ASCII number form) to reach `1` when applying "3x+1".**

### Tl;dr

The password to get to the flag is 6 characters long, with each character (represented in ASCII) taking a specific number of Collatz conjecture steps defined in array `&yi`.

### Solution

The first thing I did was to create a program that would calculate the number of steps it would take to reach `1` given any number. Here's the C++ code I wrote for this:
```cpp=
#include <iostream>
using namespace std;

int main() {
    
    int n;
    int count;
    cin >> n;
    int start = n;
    while (n != 1){
        if (n%2 == 0) {
            n = n/2;
        } else {
            n = (n*3) + 1;
        }
        count++
    }
    cout << start << ": " << count;
    return 0;
}
```

I then also made a bash script to run this program on all the ASCII values of the normal characters (32 to 126):

```bash=
#!/bin/bash

i=32
while [ $i -le 126]
do
    echo "$i" | ./collatzcalc
    echo ""
    i=$(( $i + 1 ))
done
```

Running the bash script gives this result:

```!
32: 5
33: 26
34: 13
35: 13
36: 21
# ...more output...
122: 20
123: 46
124: 108
125: 108
126: 108
```

So now we have the number of steps for each valid character in ASCII. Now what?

This is where I got a little lost as a struggled to find that `&yi` array. But once I found the array, the next step was clear.

Take the hex values of `&yi`...

```!
1b 00 00 00 26 00 00 00 57 00 00 00 5f 00 00 00  
76 00 00 00 09 00 00 00 
```

grab the meaningful data...

```!
1b 26 57 5f 76 09
```

and turn them into decimal numbers.

```!
27 38 87 95 118 9
```

These should be the correct number of steps for each character in the password, so let's look it up!

Editing the C++ code to filter for these numbers and give the readable character for each:

```cpp=
#include <iostream>
using namespace std;

int main() {
    
    int n;
    int count;
    cin >> n;
    int start = n;
    while (n != 1){
        if (n%2 == 0) {
            n = n/2;
        } else {
            n = (n*3) + 1;
        }
        count++
    }
    cout << start << ": " << count;
    
    if (count == 27) cout << " try this " << (char) start;
    if (count == 38) cout << " try this " << (char) start;
    if (count == 87) cout << " try this " << (char) start;
    if (count == 95) cout << " try this " << (char) start;
    if (count == 118) cout << " try this " << (char) start;
    if (count == 9) cout << " try this " << (char) start;

    return 0;
}
```

Then running the bash script again gives us these results:

```!
# other ouput...
65: 27 try this A
66: 27 try this B
67: 27 try this C
# ...
80: 9 try this P
# ...
84: 9 try this T
85: 9 try this U
# ...
97: 118 try this a
# ...
103: 87 try this g
104: 12
105: 38 try this i
# ...
121: 95 try this y
# ...
```

Matching up the numbers and letters gives us this:

```!
27 38 87 95 118 9
A  i  g  y  a   P
B               T
C               U
```

This gives us only 9 passwords to try, so start from the top!
![image](https://hackmd.io/_uploads/SJpI51wY1x.png)\
Well hey! The first try works! In fact, all combinations of the first and last letters work, but clearly **the intended password is: `BigyaP`.**

And that gives us the flag!\
***Flag: `lactf{the_only_valid_solution_is_BigyaP}`***

## rev/crypt-of-the-necropuzzler

![image](https://hackmd.io/_uploads/H1S4ikwt1e.png)
Taking a look at the challenge description, it looks like this program supposed resemble a puzzle. With not much else to look at, lets download the script and get to work.

First things first, lets try running it and seeing what happens:\
![image](https://hackmd.io/_uploads/Hyl73yPYJe.png)\
Ah, so we are greeted by a small 7x7 grid made of `_` and `#`. One cell of the grid is wrapped by `[]`. Testing out various key presses reveals various controls:
- The `WASD` keys moves the cursor (represented by `[]`) orthogonally.
- The `X` key changes the `_` highlighted by the cursor to a `#` and vice versa (notably it does not change the `#`s that are on the grid to begin with).
- The `C` key spits out an `Incorrect!` when pressed (this is likely used for checking our work in the puzzle).
- And finally the `Q` key quits the program.

With not much other info to go on, we take a look at the code.

### Full Code Breakdown

The first thing that sticks out in the program is this long array (2 of them!):\
![image](https://hackmd.io/_uploads/H1kPGMvtyg.png)\
Given that we know that the program uses a 7x7 grid, it's likely that these arrays represent the grid in some way. In fact, taking a closer look at the first array (`g` and `f`) we can find that the ones correspond to the `#`s in the starting grid, and presumably the zeros represent the `_`s. There is also the second array (`n`) that seems to assign values to each cell of the grid, but the purpose of this is unclear at the moment.

Next we have the `decrypt_flag(k)` function:\
![image](https://hackmd.io/_uploads/BkYnXGwKyg.png)\
This one is pretty straight-forward. This function will decrypt the flag and print it out. Our goal will be to try to get this function to run from main.

Our next function is unhelpfully named `t(a,b,s=None)`:\
![image](https://hackmd.io/_uploads/rkcdNfDFye.png)\
Before the function, we get a small array `m` which contains values for our `WASD` controls. This seems to be the main driver for moving the cursor, as well as defining the surrounding cells.

The `t` function itself also has obfuscated variables, but looking at context clues can help us identify what the function and each variable actually means.

`s` is clearly a set, and we just defined `m`, so what about the other variables?

In the long if statement, there is a comparison `g[x*7+y]==g[a*7+b]` between two elements of the `g` array. The format in which these elements are being called is highly indicative of a **flattened 2d array**, with the first variable serving as the row and the second serving as the column of the 2d array. This makes sense seeing that we are working with a grid. This means that **`x, y` and `a, b` are likely coordinates for the grid.** Other uses of `x, y` and `a, b` in the program will be coordinates as well.

As for the function itself, it first adds the coordinates `a, b` to the set. Then, using the array `m`, define every surrounding cell and check if the value of the current cell and the surrounding cell in grid `g` are equal. And if the surrounding cell within the grid and is not already in the set `s`, recursively call function `t`.

Later research would have me discover that this is a [depth first search algorithm](https://en.wikipedia.org/wiki/Depth-first_search), which allows for traversal through trees, graphs, and in this case, a grid.

Given the previous information about `g`, we can conclude that **function `t` returns a set of coordinates that corresponds to an area on the grid that consists of orthogonally adjacent `#`s or `_`s.**

For example, lets say we have a grid that looks like this:

```!
# # #
# _ _ 
# _ #
```

Calling the function on the top-left cell of the grid would return the coordinates of all the `#`s in the top row and left column, but none of the `_`s and not the bottom-right `#`.

Finally, we have our main section of code, which I will break up into multiple parts. This section is encased within a while loop and can be split into several cases.\
![image](https://hackmd.io/_uploads/Sk5ThGDFkg.png)\
First, we have the return of our `a, b` variables representing our cursor coordinates, and a new variable `d`, which I will explain now.

- The `if d:` case prints out our current grid state, making `d` a flag (not to be confused with a CTF flag) for doing this print whenever there's a change in the visual presentation of the grid.
- The `try:` reads in our input to the variable `c`. The various `break`s just quit the program.

![image](https://hackmd.io/_uploads/HkmbyQDtke.png)\
Nothing interesting here.

- The `c=='q'` case is our quit key.
- The `c=='x'` case changes the cell if it was originally empty.
- The `v:=m.get(c):` case moves the cursor.

![image](https://hackmd.io/_uploads/ByW6yXwYyl.png)\
Ok, now this is the important bit. The `c=='c':` case seems to check our solution to the puzzle, but what is it checking for?

The first thing we see is our `decrypt_flag()` function that we're aiming for, wrapped in an `if p:` condition. Basically we want to keep `p=1` and avoid `p=0` to win.

Looking at the rest of the code snippet, we see we're iterating through the entire grid, calling our function `t`, and putting the result in `k`, meaning we're grabbing and looking at those previous defined areas of connected cells. Then for every cell in the area it does this:

`v[n[x*7+y]]+=1`

Ok, so we have a small array `v` which is getting incremented by 1. Looks like `v` is counting something, but what?

This is where we find the purpose of the second grid array `n`. Each number in this array corresponds to an index of `v`, basically assigning each cell in the grid a number. Given this information, it looks like `v` represents a count of these assigned cell numbers for the given area.

Finally, the `if any(` statement checks if the last 3 values of `v` (index 1, 2, and 3) equal either 0, 2, or neither. If any of those values equal neither 0 nor 2, then we get our fail state of `p=0`. This means we only want our areas to contain 0 or 2 of the same non-zero numbers, or in other words, only unique pairs.

Combining all this information together, we find that our checker code **checks to make sure that all areas of similar, orthogonally connected cells only contain unique pairs of 1, 2, or 3.**

### Tl;dr

Each cell in the grid is given a value from 0 to 3 by array `n`, and the code that checks the solution checks to make sure that all areas of similar (all `_` or all `#`), orthogonally connected cells only contain unique pairs of 1, 2, or 3 while ignoring 0s.

With this information in mind, we can now solve the puzzle!

### Solution

Now that we know the rules of the puzzle that we have to solve, lets write out the grid with the assigned values from `n` for each cell, and write the grid as shown when run in the program for good measure.

```
1 1 0 0 0 0 0   [_]_ _ _ _ _ _
0 1 0 2 0 0 0    _ # _ _ _ _ _
0 0 3 1 0 0 0    _ _ _ # _ _ _
0 0 1 0 1 0 0    _ _ # _ # _ _
0 0 0 1 3 0 0    _ _ _ # _ _ _
0 1 0 1 0 1 0    _ _ _ _ _ _ _
0 0 2 2 2 0 0    _ _ # _ # _ #
```

At this point, solving the puzzle relies entirely on our traditional puzzle solving skills. Writing out the values by hand would be the easiest and most effective way of visualizing and testing solutions to the puzzle.

As for how to solve the puzzle, the best way is to recognize that the pair of 3s must occupy the same area, and the two pairs of 2s must occupy different areas. The pairing of the twos are already predetermined the starting grid. This actually makes the board very restrictive - the only way to connect the pair of 2s marked by `#`s without cutting off the other pair of 2s is by making a large loop of `#`s along the edge of the grid.

This is the solution I worked out on a sticky note (a little unclear from the eraser marks):\
![image](https://hackmd.io/_uploads/r1Tf1VwKkg.png)

Here is the solution input into the program:\
![image](https://hackmd.io/_uploads/HJf9k4vt1x.png)

And that gives us the flag!\
***Flag: `lactf{i_may_or_may_not_have_blatantly_stolen_a_taiji_puzzle_lol}`***

#### Extra Note

As the flag states, this puzzle is a direct copy of a puzzle in the game [Taiji](https://taiji-game.com/). Here is the screenshot of the puzzle in-game (Courtesy of challenge-maker aplet123 via Discord):\
![image](https://hackmd.io/_uploads/rJUaeVvtJx.png)\
You can see the resemblance right? Basically the same puzzle except for the bottom right corner.

## Conclusion

Dang this was a banger of a first CTF. I loved the little game theme that went into the rev/ category. If all CTFs are like this, I'm very hopeful about my continued participation.

Thanks for reading this writeup! I hope that this will be the first of many.
