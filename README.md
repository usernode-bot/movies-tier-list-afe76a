# Movies Tier List

A shared tier list for the group's favourite movies. Anyone in the project
can add a movie by name, and anyone can move it into one of five fixed
tiers, from S (best) to D (worst). New movies wait in "Waiting to be
sorted" until someone places them. There is one list, and everyone edits
it: a move is seen by the others the next time the page loads. Only the
person who added a movie can remove it.

Tap a movie to open its panel: move it to any tier, send it back to
waiting, remove it if it is yours, or report it if it is not.

The app runs on Homeroom: sign-in comes from the platform as an iframe
token, the list lives in the app's own Postgres database, and the look
follows the viewer's Homeroom light or dark theme.

On staging, `?demo=1` opens a populated preview built from made-up movies
and friends (see "Staging demo: made-up movies and friends" at the top of
the screen).
