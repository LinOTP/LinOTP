submit_rule(S) :-
   gerrit:default_submit(X),
   X =.. [submit | Ls],
   add_non_author_verification(Ls, R),
   S =.. [submit | R].

add_non_author_verification(S1, S2) :-
  gerrit:commit_author(A),
  gerrit:commit_label(label('Verified', 1), V),
  V \= A, !,
  S2 = [label('Non-Author-Verification', ok(V)) | S1].

add_non_author_verification(S1, [label('Non-Author-Verification', need(_)) | S1]).
