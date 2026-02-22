import { useEffect, useState } from 'react';
import { CollectionReference, DocumentData, onSnapshot, query, QueryConstraint } from 'firebase/firestore';

export function useFirestoreCollection<T = DocumentData>(
  collectionRef: CollectionReference<DocumentData> | null,
  ...constraints: QueryConstraint[]
) {
  const [data, setData] = useState<T[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    // Return early if collectionRef is null
    if (!collectionRef) {
      setLoading(false);
      return;
    }

    const q = constraints.length
      ? query(collectionRef as unknown as any, ...constraints)
      : query(collectionRef as unknown as any);
    const unsub = onSnapshot(
      q,
      (snap) => {
        const items = snap.docs.map((d) => ({ id: d.id, ...(d.data() as T) } as T));
        setData(items);
        setLoading(false);
      },
      (err) => {
        setError(err as Error);
        setLoading(false);
      },
    );
    return () => unsub();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [collectionRef]);

  return { data, loading, error } as const;
}


