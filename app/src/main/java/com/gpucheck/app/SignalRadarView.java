package com.gpucheck.app;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.RadialGradient;
import android.graphics.RectF;
import android.graphics.Shader;
import android.view.View;

/**
 * A quiet instrument illustration for the current monitoring state.
 *
 * The geometry is decorative, not a chart or a simulated scan. It has no clock,
 * animation, or background work; only new monitoring state invalidates it.
 * Adjacent text provides the actual values and the accessible description.
 */
public final class SignalRadarView extends View {
    private static final int BORDER = Color.rgb(38, 50, 66);
    private static final int MUTED = Color.rgb(107, 125, 145);
    private static final int SURFACE = Color.rgb(16, 25, 36);
    private static final int DEFAULT_SIGNAL = Color.rgb(214, 245, 139);
    private static final float VIEWBOX = 128f;

    private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final RectF bounds = new RectF();
    private final float density;
    private boolean running;
    private boolean hasSample;
    private int signalColor = DEFAULT_SIGNAL;
    private Shader halo;

    public SignalRadarView(Context context) {
        super(context);
        density = getResources().getDisplayMetrics().density;
        setImportantForAccessibility(IMPORTANT_FOR_ACCESSIBILITY_NO);
        setFocusable(false);
        updateHalo();
    }

    /** Update the instrument only when its semantic state actually changes. */
    public void setSignalState(boolean running, boolean hasSample, int color) {
        if (this.running == running && this.hasSample == hasSample && signalColor == color) return;
        this.running = running;
        this.hasSample = hasSample;
        signalColor = color;
        updateHalo();
        invalidate();
    }

    private void updateHalo() {
        int color = running ? signalColor : MUTED;
        halo = new RadialGradient(64f, 64f, 49f,
                alpha(color, running ? 26 : 10), Color.TRANSPARENT, Shader.TileMode.CLAMP);
    }

    @Override protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int preferred = Math.round(VIEWBOX * density);
        int width = Math.max(getSuggestedMinimumWidth(), preferred + getPaddingLeft() + getPaddingRight());
        int height = Math.max(getSuggestedMinimumHeight(), preferred + getPaddingTop() + getPaddingBottom());
        setMeasuredDimension(resolveSize(width, widthMeasureSpec), resolveSize(height, heightMeasureSpec));
    }

    @Override protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        float width = getWidth() - getPaddingLeft() - getPaddingRight();
        float height = getHeight() - getPaddingTop() - getPaddingBottom();
        float side = Math.min(width, height);
        if (side <= 0f) return;

        int saved = canvas.save();
        canvas.translate(getPaddingLeft() + (width - side) / 2f,
                getPaddingTop() + (height - side) / 2f);
        canvas.scale(side / VIEWBOX, side / VIEWBOX);

        int active = running ? signalColor : MUTED;
        paint.setStyle(Paint.Style.FILL);
        paint.setShader(halo);
        canvas.drawCircle(64f, 64f, 49f, paint);
        paint.setShader(null);

        // Four open guide axes give the instrument a technical, measured rhythm.
        stroke(BORDER, 0.7f);
        canvas.drawLine(64f, 3f, 64f, 23f, paint);
        canvas.drawLine(64f, 105f, 64f, 125f, paint);
        canvas.drawLine(3f, 64f, 23f, 64f, paint);
        canvas.drawLine(105f, 64f, 125f, 64f, paint);
        canvas.drawCircle(64f, 64f, 48f, paint);
        canvas.drawCircle(64f, 64f, 35f, paint);

        // Fixed tick positions deliberately convey no sample count or percentage.
        for (int i = 0; i < 48; i++) {
            double angle = Math.toRadians(i * 7.5 - 90);
            boolean major = i % 4 == 0;
            float inner = major ? 53f : 55f;
            stroke(major ? alpha(active, running ? 145 : 90) : BORDER, major ? 1.1f : 0.8f);
            float cos = (float) Math.cos(angle);
            float sin = (float) Math.sin(angle);
            canvas.drawLine(64f + cos * inner, 64f + sin * inner,
                    64f + cos * 58f, 64f + sin * 58f, paint);
        }

        bounds.set(16f, 16f, 112f, 112f);
        stroke(alpha(active, running ? 185 : 60), 1.5f);
        canvas.drawArc(bounds, -78f, 48f, false, paint);
        canvas.drawArc(bounds, 102f, 48f, false, paint);

        // A center chip and orthogonal traces, rather than invented radar targets.
        stroke(alpha(active, running ? 135 : 75), 1f);
        canvas.drawLine(64f, 30f, 64f, 42f, paint);
        canvas.drawLine(64f, 86f, 64f, 98f, paint);
        canvas.drawLine(30f, 64f, 42f, 64f, paint);
        canvas.drawLine(86f, 64f, 98f, 64f, paint);
        for (int i = 0; i < 4; i++) {
            float pin = 53.5f + i * 7f;
            canvas.drawLine(pin, 42f, pin, 47f, paint);
            canvas.drawLine(pin, 81f, pin, 86f, paint);
            canvas.drawLine(42f, pin, 47f, pin, paint);
            canvas.drawLine(81f, pin, 86f, pin, paint);
        }

        bounds.set(47f, 47f, 81f, 81f);
        paint.setStyle(Paint.Style.FILL);
        paint.setColor(SURFACE);
        canvas.drawRoundRect(bounds, 7f, 7f, paint);
        stroke(alpha(active, running ? 220 : 115), 1.3f);
        canvas.drawRoundRect(bounds, 7f, 7f, paint);

        bounds.set(54f, 54f, 74f, 74f);
        paint.setStyle(Paint.Style.FILL);
        paint.setColor(alpha(active, running && hasSample ? 24 : 10));
        canvas.drawRoundRect(bounds, 3f, 3f, paint);
        stroke(alpha(active, running && hasSample ? 175 : 70), 0.8f);
        canvas.drawRoundRect(bounds, 3f, 3f, paint);
        canvas.drawLine(59f, 64f, 69f, 64f, paint);
        canvas.drawLine(64f, 59f, 64f, 69f, paint);

        paint.setStyle(Paint.Style.FILL);
        paint.setColor(alpha(active, running && hasSample ? 255 : 90));
        canvas.drawCircle(64f, 30f, 1.8f, paint);
        canvas.drawCircle(98f, 64f, 1.8f, paint);
        canvas.drawCircle(64f, 98f, 1.8f, paint);
        canvas.drawCircle(30f, 64f, 1.8f, paint);
        canvas.restoreToCount(saved);
    }

    private void stroke(int color, float width) {
        paint.setStyle(Paint.Style.STROKE);
        paint.setStrokeWidth(width);
        paint.setStrokeCap(Paint.Cap.ROUND);
        paint.setColor(color);
    }

    private static int alpha(int color, int opacity) {
        return (color & 0x00ffffff) | (opacity << 24);
    }
}
