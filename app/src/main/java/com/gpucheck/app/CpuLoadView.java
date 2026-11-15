package com.gpucheck.app;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.RectF;
import android.view.View;

/**
 * A segmented visual companion to the measured, single-core CPU percentage.
 * Text beside this view retains the exact number, including values over 100%.
 * Unknown readings remain an unfilled track and must be labelled unknown in text.
 */
public final class CpuLoadView extends View {
    private static final int SEGMENTS = 16;
    private static final int TRACK = Color.rgb(38, 50, 66);

    private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final RectF segment = new RectF();
    private final float density;
    private double percentage = Double.NaN;
    private int loadColor = Color.rgb(128, 216, 235);

    public CpuLoadView(Context context) {
        super(context);
        density = getResources().getDisplayMetrics().density;
        setImportantForAccessibility(IMPORTANT_FOR_ACCESSIBILITY_NO);
        setFocusable(false);
    }

    /** Negative and non-finite values are unknown, never interpreted as zero. */
    public void setLoad(double percent, int color) {
        double next = Double.isFinite(percent) && percent >= 0 ? Math.min(percent, 100) : Double.NaN;
        if (Double.compare(percentage, next) == 0 && loadColor == color) return;
        percentage = next;
        loadColor = color;
        invalidate();
    }

    @Override protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int width = Math.max(getSuggestedMinimumWidth(), Math.round(160f * density)
                + getPaddingLeft() + getPaddingRight());
        int height = Math.max(getSuggestedMinimumHeight(), Math.round(8f * density)
                + getPaddingTop() + getPaddingBottom());
        setMeasuredDimension(resolveSize(width, widthMeasureSpec), resolveSize(height, heightMeasureSpec));
    }

    @Override protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        float width = getWidth() - getPaddingLeft() - getPaddingRight();
        float availableHeight = getHeight() - getPaddingTop() - getPaddingBottom();
        if (width <= 0f || availableHeight <= 0f) return;
        float height = Math.min(8f * density, availableHeight);
        float top = getPaddingTop() + (availableHeight - height) / 2f;
        float gap = Math.min(3f * density, width / (SEGMENTS * 3f));
        float segmentWidth = (width - gap * (SEGMENTS - 1)) / SEGMENTS;
        float radius = Math.min(2f * density, Math.min(height, segmentWidth) / 2f);
        float fillEnd = Double.isNaN(percentage) ? 0f : (float) (width * percentage / 100.0);

        for (int i = 0; i < SEGMENTS; i++) {
            float offset = i * (segmentWidth + gap);
            float left = getPaddingLeft() + offset;
            segment.set(left, top, left + segmentWidth, top + height);
            paint.setColor(TRACK);
            canvas.drawRoundRect(segment, radius, radius, paint);
            float filled = Math.min(segmentWidth, fillEnd - offset);
            if (filled <= 0f) continue;
            paint.setColor(loadColor);
            if (filled >= segmentWidth) {
                canvas.drawRoundRect(segment, radius, radius, paint);
            } else {
                int saved = canvas.save();
                canvas.clipRect(left, top, left + filled, top + height);
                canvas.drawRoundRect(segment, radius, radius, paint);
                canvas.restoreToCount(saved);
            }
        }
    }
}
